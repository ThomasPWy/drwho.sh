#!/bin/bash
#---------------------------------------- CONFIG - API KEYS -------------------------------------------------------
#* Set your API Keys
#-------------------
#hackertarget.com  -  expected input:  api_key_ht='&apikey=YOUR API KEY'
api_key_ht=''
# project honeypot
honeykey=''
#---------------------------------------- CONFIG - CUSTOMIZE PATHS TO EXECUTABLES  --------------------------------
PATH_dublin_t=$(which dublin-traceroute)
#PATH_dublin_t=""
PATH_dump_dhcp6=$(which atk6-dump_dhcp6)
#PATH_dump_dhcp6=""
PATH_dump_router6=$(which atk6-dump_router6)
#PATH_dump_router6=""
PATH_rdns6=$(which atk6-dnsrevenum6)
#PATH_rdns6=""
PATH_thcping6=$(which atk6-thcping6)
#PATH_thcping6=""
PATH_trace6=$(which atk6-trace6)
#PATH_trace6=""
PATH_httping=$(which httping)
#PATH_httping=""
PATH_ipcalc=$(which ipcalc)
#PATH_ipcalc=""
#PATH_lbd=$(which lbd)
PATH_lbd="./lbd.sh"
PATH_lynx=$(which lynx)
#PATH_lynx=""
PATH_mtr=$(which mtr)
#PATH_mtr=""
PATH_nmap=$(which nmap)
#PATH_nmap=""
PATH_sslscan=$(which sslscan)
#PATH_sslscan=""
#PATH_testssl=$(which testssl)
PATH_testssl="./testssl.sh/testssl.sh"
PATH_tracepath=$(which tracepath)
#PATH_tracepath=""
PATH_wfuzz=$(which wfuzz)
#PATH_wfuzz""
PATH_whatweb=$(which whatweb)
#PATH_whatweb=""

#------------------------------------------------------------------------------------------------------------------
f_error_message(){
local s="$*"
echo -e "\nERROR: $s is not installed on your system. Please make sure that at least the essential dependencies are satisfied."
echo -e "\nDependencies (essential): curl, dnsutils (installs dig & host), jq, ipcalc, lynx, nmap, openssl, whois"
echo -e "\nDependencies (recommended): dublin-traceroute, mtr, sipcalc, testssl, thc-ipv6, tracepath, wfuzz, whatweb\n"
}
if ! type curl &> /dev/null; then
f_error_message "curl" ; exit 1 ; fi
if ! type dig &> /dev/null; then
f_error_message "dig (dnsutils)" ; exit 1 ; fi
if ! type jq &> /dev/null; then
f_error_message "jq" ; exit 1 ; fi
if [ -z ${PATH_nmap} ] ; then 
f_error_message "nmap" ; exit 1 ; fi
if ! type whois &> /dev/null; then
f_error_message "whois" ; exit 1 ; fi

#********************** VARIABLES - TEXT COLOURS & BOLDNESS  ***********************
B='\e[34m' ; D='\e[0m' ; GREEN='\e[32m' ; G2='\e[38;5;035m' ; R='\e[31m' ; bold="\e[1m"
#********************** VARIABLES - REGEX  ***********************
REGEX_IP4="^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"
REGEX_DOMAIN="^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,5}$"
#********************** VARIABLES - CURL USER AGENTS ***********************
ua_moz="Mozilla/5.0"
#********************** VARIABLES - WFUZZ WORD LIST(S) ***********************
wordl_wfuzz1="/usr/share/wfuzz/wordlist/general/medium.txt"
#********************** VARIABLES - DEFAULTS & TEMPORARY WORKING DIRECTORY ***********************
tempdir="${PWD}/drwho_temp" ; outdir="${PWD}/drwho_temp"; folder="not saving results"
option_connect="1" ; conn="${GREEN}true${D}" ; report="false" ; quiet_dump="false" ; type_mx="false"

#********************** NMAP - PORTS & NSE SCRIPTS ***********************
ports_net="T:21,T:22,T:23,T:25,T:53,U:53,T:80,T:88,T:110,T:111,U:123,T:135,T:139,T:143,T:443,T:445,T:514,T:993,T:995,T:1025,T:1434,T:1723,T:3306,T:3389,T:5004,T:5005,U:5060,T:5900,T:8080,T:8443"
nmap_top15_ntp="T:21,T:22,T:23,T:25,T:53,U:53,T:80,T:110,U:123,T:135,T:139,T:143,T:443,T:445,T:3306,T:3389,T:8080"
ports_lan="T:21,T:22,T:23,T:25,T:53,U:53,T:79,T:80,T:110,U:123,T:135,U:137,T:139,U:161,T:443,T:502,T:631,T:1025,T:1434,T:3306,T:3389,T:5004,T:5005,U:5060,T:5900,T:8080,U:47808"
ports_web1="T:80,T:443,T:3306"
ports_web2="T:21,T:22,T:23,T:80,T:443,T:3306,T:8080,T:8443"
ports_web3="T:21,T:22,T:23,T:80,T:135,T:443,T:1025,T:1434,T:3306,T:8000,T:8080,T:8443,T:9800,T:10000,T:50075"
ports_dns="U:53,T:22,T:25,T:53,T:80,T:110,T:143,T:443,T:465,T:587,T:993,T:995"
nse_basic="banner,http-server-header,https-redirect"
nse_dns1="smtp-commands,smtp-ntlm-info,imap-capabilities,imap-ntlm-info,pop3-capabilities,pop3-ntlm-info"
nse_dns2="smtp-commands,smtp-ntlm-info,imap-capabilities,imap-ntlm-info,pop3-capabilities,pop3-ntlm-info,dns-nsid,dns-recursion"
nse_dns3="smtp-open-relay,smtp-enum-users"
nse_ssh="ssh2-enum-algos,ssh-auth-methods"
nse_net="banner,cups-info,hadoop-namenode-info,http-server-header,ssl-cert,unusual-port"
nse_lan="banner,finger,http-server-header,bacnet-info,modbus-discover,sip-methods,smb-enum-shares,nfs-showmount,ntp-info"
nse_lan_os="smb-os-discovery,snmp-info,snmp-netstat,rpcinfo"
nse_lan_vulners="ftp-anon,ms-sql-empty-password,ms-sql-ntlm-info,mysql-empty-password,http-malware-host,http-methods,vulners"
nse_web_safe="http-apache-server-status,http-generator,http-php-version,http-mobileversion-checker,http-affiliate-id,http-referer-checker,mysql-info"
nse_web1="http-auth,http-auth-finder,http-csrf,http-phpself-xss,http-dombased-xss,http-stored-xss,http-unsafe-output-escaping,http-rfi-spider,ftp-anon,mysql-empty-password,ssh2-enum-algos,vmware-version,http-malware-host,http-enum,http-phpmyadmin-dir-traversal,http-webdav-scan,xmlrpc-methods,http-methods"
nse_web2="http-wordpress-enum,http-jsonp-detection,http-open-proxy,http-backup-finder,smtp-strangeport,http-slowloris-check,hadoop-namenode-info,hadoop-datanode-info,rpcinfo"
#********************** SUBPAGES - CONTACTS ***********************
subpages1="
blog
career
contact
contact-us
en/career
kontakt
legal
services
support
jobs
de/karriere
karriere
news
de/kontakt
impressum
"
subpages2="
blog
jobs
support
"
#********************** DNS BLOCKLISTS ***********************
blocklists_host="
all.bl.blocklist.de
all.s5h.net
b.barracudacentral.org
bl.spamcop.net
bogons.cymru.com
dnsbl-1.uceprotect.net
dnsbl-2.uceprotect.net
dnsbl-3.uceprotect.net
dnsbl.dronebl.org
dnsbl.tornevall.org
dyn.nszones.com
ix.dnsbl.manitu.net
noptr.spamrats.com
phishing.rbl.msrbl.net
recent.spam.dnsbl.sorbs.net
smtp.dnsbl.sorbs.net
talosintelligence.com
"
blocklists_net="
all.s5h.net
b.barracudacentral.org
bl.spamcop.net
dnsbl-1.uceprotect.net
dnsbl-2.uceprotect.net
dnsbl-3.uceprotect.net
dyn.nszones.com
ips.backscatterer.org
noptr.spamrats.com
recent.spam.dnsbl.sorbs.net
tor.dan.me.uk
zen.spamhaus.org
"
blocklists_domain="
all.s5h.net
b.barracudacentral.org
all.bl.blocklist.de
bl.spamcop.net
dnsbl.dronebl.org
dnsbl-1.uceprotect.net
dnsbl-2.uceprotect.net
dnsbl-3.uceprotect.net
dyn.nszones.com
ix.dnsbl.manitu.net
phishing.rbl.msrbl.net
recent.spam.dnsbl.sorbs.net
smtp.dnsbl.sorbs.net
talosintelligence.com
"
#********************** START MENU (GLOBAL OPTIONS) & BANNER ***********************
f_startMenu() {
echo -e "\n  c)  TARGET-CONNECT-/NON-CONNECT-MODES"
echo " cc)  CLEAR THE SCREEN"
echo "  h)  HELP"
echo -e "${B}  o)  OPTIONS${D}"
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
echo -e "\033[3;39m  \"whois the Doctor? Who? Dr Who?\" ${D}"
f_startMenu

#********************** MANAGE TARGET INTERACTION ***********************
f_targetCONNECT() {
echo -e "\n${B}Option >${G2} Target Interaction ${B}>${D} Send packets from your IP to target systems?"
echo -e "\n${G2}[1] YES${D}\n"
echo "(Recommended for domain recon, required for web server- & most traceroute-, ping- & port scan options)"
echo -e "\n${R}[0] NO ${D}\n"
echo "(Use 3rd party sources only)"
echo -e -n "\n${B}  ?${D}  " ; read option_connect
if ! [ $option_connect = "0" ] ; then
conn="${GREEN}true${D}" ; else
conn="${R}false${D}" ; fi
export option_connect ; export conn
}
f_WARNING(){
echo -e "\n${R} Warning >${D} This option requires sending packets to target systems!"
echo -e "\nPlease deactivate safe mode via options a) or s)." ; echo -e "\n${R}${IT}Aborting...${D}"
}
#********************** SET TEMPORARY & PERMANENT DIRECTORIES ***********************
f_makeNewDir(){
if [ -d $tempdir ]; then
rm -rf $tempdir ; mkdir $tempdir ; else
mkdir $tempdir ; fi
}
f_removeDir(){
if [ -d $tempdir ]; then
rm -rf $tempdir ; fi
}
#********************** GET INTERNET REGISTRY ***********************
f_getRIR(){
local s="$*"; rir=$(curl -s -m 7 --location --request GET "https://stat.ripe.net/data/rir/data.json?resource=${s}" | jq -r '.data.rirs[0].rir' | cut -d ' ' -f 1 |
tr -d ' ' | tr [:upper:] [:lower:]); export rir
}
#********************** GENERATE REPORTS FROM OUTPUT ***********************
f_REPORT(){
echo -e -n "\n${B}Set folder > ${D}HOME/${B}dir_name >>${D} " ; read dirname
if [ -n "$dirname" ] ; then
mkdir $HOME/$dirname ; outdir="$HOME/$dirname" ; report="true" ; export outdir ; export report; export folder
folder="$dirname" ; f_targetCONNECT ; fi
}
#*********** DEFAULT NAME SERVERS, NETWORK INTERFACES; OUTPUT *************
f_systemDNS(){
if ! type resolvectl &> /dev/null; then
grep 'nameserver' /etc/resolve.conf; else
resolvectl status | sed -e '/./{H;$!d;}' -e 'x;/Current DNS Server:/!d;' | sed '/setting:/d' | sed '/Scopes:/d' | sed '/DNSSEC/d' |
sed 's/DNS Servers:/DNS Servers:\n/' | sed 's/^ *//' | sed '/^$/d' | sed '/Link/{x;p;x}'; fi
}
f_IFLIST() {
f_Long
if [[ $(uname -o) =~ "Android" ]] ; then
echo -e "INTERFACES\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
echo -e "ETHERNET"
ip addr show | grep -B 1 -w 'link/ether' | grep -A 1 -w 'state UP' | cut -d ' ' -f 2- | sed 's/^ *//' | sed 's/link\/ether/ link\/ether/g' |
sed '/state UP/{x;p;x;G}' | sed 's/: </: \n\n</g' ; echo -e "\n\nIPV4"
ip -4 addr show | grep -A 2 'state UP' | cut -d ' ' -f 2- | sed 's/^ *//' | sed 's/inet/ inet/g' | sed 's/valid_lft/ valid_lft/g' |
sed '/state UP/{x;p;x;G}' | sed '/valid_lft/{x;p;x;G}' | sed 's/: </: \n\n</g'; echo -e "\n\nIPV6"
ip -6 addr show | grep -A 2 'state UP' | cut -d ' ' -f 2- | sed 's/^ *//' | sed 's/inet/ inet/g' | sed 's/valid_lft/ valid_lft/g' |
sed '/state UP/{x;p;x;G}' | sed '/valid_lft/{x;p;x;G}' | sed 's/: </: \n\n</g'
f_Long; echo -e "ROUTES\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' ; ip route ; else
nmap --iflist | sed '/Starting Nmap/d' | sed '/INTERFACES/G' | sed '/ROUTES/{x;p;x;G}' | sed '/DEV/G' | sed 's/INTERFACES/ INTERFACES /' |
sed 's/ROUTES/ ROUTES /' ; fi ; echo ''
}
#********************** OUTPUT - BASIC FORMATTING ***********************
f_textfileBanner(){
local s="$*";echo -e "\n ---------------" ; echo -e "  drwho.sh" ; echo -e " ---------------\n"
echo -e "https://github.com/ThomasPWy/drwho.sh,  Author: Thomas Wy,  Version: 2.0 (Dec 2021)"; f_Long
echo -e "\nDate:    $(date)"; echo -e "\nTarget:  $s\n"
}
f_whoisFORMAT(){
cat $tempdir/whois_temp | sed 's/% Information related to /Information related to /' | sed '/Source:/d' | sed '/fax:/d' | sed '/remarks:/d' |
sed 's/% Abuse contact/Abuse contact/' | sed '/^#/d' | sed '/%/d' | sed '/^$/d' | sed '/Abuse contact/{x;p;x;G;}' |
sed 's/Abuse contact for .*. is/\[@\] /' | sed '/Information related/i \_________________________________________________________\n' |
sed '/Information related/G' | sed 's/Information related to/* /'
}
f_NMAP_OUT(){
grep -E "scan report|OS guesses:|rDNS|not scanned|Host is|PORT|*./tcp|*./udp|\||\|_|Network Distance:|Running:|OS details:|Device type:|Nmap done" $tempdir/nmap.txt |
sed '/PORT/{x;p;x;}' | sed '/\/tcp /G'| sed '/\/udp /G' | sed '/Nmap scan report for/G' | sed 's/OS guesses:/OS guesses:\n/' |
sed '/Nmap scan report/i \______________________________________________________________________________\n' | sed '/Host is up/G' |
sed 's/Nmap scan report for/*/' | sed '/\/tcp/i \\n----------------------------------------------------------\n' | sed '/CVE/i \__\n' | 
sed '/\/udp/i \\n----------------------------------------------------------\n' | sed 's/Device type:/Device type:       /g' |
sed '/OS guesses:/i \\n----------------------------------------------------------\n' | sed '/Aggressive OS guesses:/G' | sed 's/Host is/  Host is/g' |
sed '/Device type:/i \\n----------------------------------------------------------\n' | sed 's/Running:/Running:           /g' |
sed '/Network Distance:/i \\n----------------------------------------------------------\n' |
sed '/Nmap done:/i \\n----------------------------------------------------------\n' | sed 's/OS details:/\nOS details:        /' | fmt -s -w 120
}
f_www_test_HEADER(){
echo -e "\n"; f_Long
if  [ $option_www = "1" ] ; then
headline="WEB SERVER HEALTH CHECK"
elif [ $option_www = "3" ] ; then
headline="WEB SITE OVERVIEW"; else
headline="WEB SERVER TESTING"; fi
echo "[+]  $headline | UTC: $(date --utc)" ; f_Long
curl -s "http://ip-api.com/json/?fields=54537985" > $tempdir/local.json
offset=$(($(jq -r '.offset' $tempdir/local.json) / 3600)); org=$(jq -r '.org' $tempdir/local.json)
asn=$(jq -r '.as' $tempdir/local.json | cut -d ' ' -f 1 | sed 's/^*//' | sed 's/AS/AS /')
loc=$(jq -r '.country' $tempdir/local.json)
if [ -n "$curl_ua" ] ; then
ua_out="($ua_moz)" ; else
ua_out="(curl default)" ; fi
echo -e "\nYour IP:     $(jq -r '.query' $tempdir/local.json) ($asn) | Geo: $loc (UTC $offset h)"
echo -e "\nUser Agent:  $(curl -V | head -1 | cut -d ' ' -f -2) $ua_out"
}
#********************** SEPARATORS ***********************
f_Long(){
echo -e "_______________________________________________________________________________\n"
}
f_Short(){
echo -e "______________________________________________________________\n"
}
f_Short2(){
echo -e "\n________________________________________________\n"
}
f_Shorter(){
echo -e "____________________________________\n"
}
f_Shortest(){
echo -e "________________\n"
}
#********************** MAIN OPTIONS MENU ***********************
f_Menu(){
out="$tempdir/out" ; f_Long
echo -e "\n  ${B}Directory      >${D}  $folder"
echo -e "\n  ${B}TargetConnect  >  $conn"
echo -e "\n  ${B}Object/Target Categories\n"
echo -e "${B}   a)  ${D}Abuse Contact Finder"
echo -e "${B}  as)  ${D}ASNs"
echo -e "${B}  bl)  ${D}IP Reputation- & DNS Blocklist-Check (IPv4-Networks/-Hosts)"
echo -e "${B}   d)  ${D}Domain Recon"
echo -e "${B} dns)  ${D}DNS Records, NS- & MX Servers"
echo -e "${B}   g)  ${D}Rev. GoogleAnalytics Search"
echo -e "${B}   i)  ${D}Network Interfaces & Public IP"
echo -e "${B}  ip)  ${D}Hosts (IPv4/IPv6/Hostname)"
echo -e "${B}  ix)  ${D}Internet Exchanges (IX)"
echo -e "${B}   l)  ${D}LAN"
echo -e "${B}   n)  ${D}Networks"
echo -e "${B}   p)  ${D}NMAP Port- & Vulnerability Scans"
echo -e "${B}   t)  ${D}Tracerouting"
echo -e "${B}   w)  ${D}Whois (Inverse, Organisation/PoC- & Bulk Lookup Options)"
echo -e "${B} www)  ${D}Web Servers"
echo -e "\n${B}   c)  ${D}TOGGLE TARGET - CONNECT / NON-CONNECT MODES"
echo -e "${B}   s)  ${D}SAVE RESULTS"
echo -e "${B}   m)  ${D}MAIN MENU"
echo -e "${B}   q)  ${D}QUIT"
}

#********************** SERVER/WEBSITE - STATUS, PAGE DUMP, MTR, PAGE LOADING TIMES, CDN & LOAD BALANCING DETECTION ***********************
f_writeOUT(){
local s="$*" ; curl -m 10 ${curl_array[@]} ${curl_ua} ${s} 2>$tempdir/curl -D $tempdir/headers -o $tempdir/page.html -w \
"
URL:             %{url_effective}
IP:              %{remote_ip}
Status:          HTTP %{http_version} %{response_code}  (%{remote_ip})
Time Total:      %{time_total} s
" > $tempdir/response
cat $tempdir/page.html | tr "\'" '\"' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' > $tempdir/page_src
cat $tempdir/page_src | sed 's/</ </g' | sed 's/<script/\n\n<script/g' | sed 's/<\/script>/<\/script>\n\n/g' | grep -E -A 10 "<script" |
sed 's/\/ui\//./g' | sed 's/jquery\/jquery\//jquery/g' | sed 's/jquery\/jquery/jquery/g' | sed 's/^[ \t]*//;s/[ \t]*$//' |
sed '/^$/d' | tr [:upper:] [:lower:] | sed 's/.min//g' | sed 's/-min//g' | tee $tempdir/cms > $tempdir/src_scripts
cat $tempdir/page_src | tr -d '"' | sed 's/= /=/g' | sed 's/ = /=/g' | sed 's/<noscript>/\n<noscript>/g' | sed 's/<meta/\n<meta/g' |
sed 's/^[ \t]*//;s/[ \t]*$//' > $tempdir/noquotes; grep 'link' $tempdir/noquotes | tee -a $tempdir/cms > $tempdir/page_links
grep -A 7 '<!--' $tempdir/page_src | tee -a $tempdir/cms  > $tempdir/comments
sed -n '/<head/,/<\/head>/p' $tempdir/page_src >> $tempdir/cms ; cat $tempdir/headers >> $tempdir/cms
cat $tempdir/curl | tr -d '<*>' | sed 's/^ *//' > $tempdir/curl_trimmed
if [ $report = "true" ] ; then
if [ $domain_enum = "true" ] || [ $ssl_details = "true" ] ; then
cat $tempdir/page.html > $outdir/SOURCE.${s}.html ; fi ; fi
}
f_curlHandshake(){
local s="$*" ; cat $tempdir/stat | sed '/^$/d' | sed 's/ = /=/' | sed 's/*/ * /g' | sed 's/</ < /g' | sed 's/>/ > /g' |
grep -E -i "HTTP/.*|HTTP1.*|HTTP2|Re-using|* Connection|ALPN|ID|SSL connection|SSL certificate|server:|Server certificate:|> GET|> HEAD|handshake|connected to|expire|squid|via:|location:|rev-proxy|x-client-location:|accepted to use|CN=|date:|content-length:|SPDY|cache-control:|content-length" | sed '/P3P:/d' | sed '/[Ff]eature-[Pp]olicy:/d' | sed '/[Pp]ermissions-[Pp]olicy:/d' | sed '/Server [Cc]ertificate:/a \___________________________________\n' | sed '/[Cc]ontent-[Ss]ecurity-[Pp]olicy:/d' |
sed '/SSL connection using/i \\n---------------------------------------------------------------------\n' | sed '/Server certificate:/{x;p;x;}' |
sed '/Connected to /a \________________________________________________________________________\n\n' | sed -e :a -e 's/\(.*[0-9]\)\([0-9]\{4\}\)/\1/;ta' |
sed '/Connected to /i \\n________________________________________________________________________\n' | sed '/[Cc]ontent-[Ll]anguage/d' |
sed '/SSL [Cc]ertificate verify/a \\n---------------------------------------------------------------------\n' | fmt -w 120 -s
}
f_serverINSTANCE(){
local s="$*"
curl -m 10 ${target} ${st_array[@]} ${ua} --resolve "${target}:443:${s}" --trace-time 2>$tempdir/stat -o $tempdir/p2.html -D $tempdir/h2 -w \
"
URL:           %{url_effective}
st:  HTTP %{http_version} %{response_code}
rd:  %{num_redirects}
IP:            %{remote_ip}\n
Status:        HTTP %{http_version} %{response_code},  redirects: %{num_redirects}
Resp.Times:    Total:  %{time_total} s DNS: %{time_namelookup} s SSL: %{time_appconnect}
DNS Lookup:  %{time_namelookup} s
TCP Hshake:  %{time_connect} s
SSL Hshake:  %{time_appconnect} s
Total Time:  %{time_total} s
" > $tempdir/status_raw
page_sha1=$(sha1sum $tempdir/page.html | cut -d ' ' -f 1)
p2_sha1=$(sha1sum $tempdir/p2.html | cut -d ' ' -f 1) ; echo -e "\n$eff_ip" >> $tempdir/web_hashes ; echo $p2_sha1 >> $tempdir/web_hashes
time_stamp=$(date)
grep -E "^URL:|^IP:|^Status:|^Resp.Times:" $tempdir/status_raw | sed 's/DNS:/ | DNS:/g' | sed 's/SSL:/ | SSL:/g' | sed '/^$/d' |
sed '/Status:/G' > $tempdir/status.txt
cat $tempdir/stat | cut -d ' ' -f 3- | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' | sed 's/server:/Server:/g' | sed 's/via:/Via:/g' |
sed 's/cache-control:/Cache-Control:/g' | sed 's/Cache-control/Cache-Control:/g' > $tempdir/stat_trimmed
eff_ip=$(grep -E "^IP:"  $tempdir/status_raw | awk '{print $NF}' | sed 's/^[ \t]*//;s/[ \t]*$//' | tr -d ' ')
status=$(grep -E "^st:" $tempdir/status_raw | cut -d ':' -f 2- | sed 's/^ *//' | sed 's/HTTP /HTTP\//')
redir=$(grep -E "^rd:" $tempdir/status_raw | awk '{print $NF}' | tr -d ' ')
user_agent=$(grep -i 'user-agent:' $tempdir/stat_trimmed | tail -1 | cut -d ':' -f 2- | sed 's/^ *//')
httpserv=$(grep -E -i "^Server:" $tempdir/h2 | cut -d ':' -f 2 | sed 's/^[ \t]*//;s/[ \t]*$//' | tail -1)
endpoint=$(grep 'Connected to' $tempdir/stat_trimmed | tail -1 | awk '{print $3,$4,$5,$6}' | sed 's/ port /:/')
echo '' | tee $tempdir/writeout > $tempdir/HANDSHAKE.txt; f_Long | tee -a $tempdir/writeout >> $tempdir/HANDSHAKE.txt
echo -e "[+] $target [$s] | SSL HANDSHAKE" | tee -a $tempdir/writeout >> $tempdir/HANDSHAKE.txt
f_Long | tee -a $tempdir/writeout >> $tempdir/HANDSHAKE.txt; echo '' | tee -a $tempdir/writeout >> $tempdir/HANDSHAKE.txt
echo -e "SystemTime:    $(date)" >> $tempdir/HANDSHAKE.txt; echo -e "User Agent:    $user_agent\n" >> $tempdir/HANDSHAKE.txt
cat $tempdir/status.txt | sed G >> $tempdir/HANDSHAKE.txt; f_curlHandshake | tee -a $tempdir/writeout >> $tempdir/HANDSHAKE.txt
cat $tempdir/HANDSHAKE.txt >> ${outdir}/CURL_write_out.${target}.txt; cat $tempdir/writeout >> $tempdir/writeout.${target}.txt
header_date=$(grep -E -i "^date:" $tempdir/h2 | tail -1 | cut -d ' ' -f 2- | sed 's/^ *//')
echo '' ; f_Long; echo "[+] SERV. INSTANCE |  $s  | STATUS: $status | REDIR: $redir" ; f_Long
echo -e "\nRequest:       $target ($s)" ; echo -e "\nEndpoint:      $endpoint"
if [ -n "$header_date" ] ; then
header_date="$header_date" ; else
header_date="NA" ; fi
if [ $domain_enum = "true" ] ; then
echo -e "\nHeader Date:   $header_date\n\n"; else
echo -e "\n\nHeader Date:   $header_date"; fi
if [ $domain_enum = "true" ]; then
grep -E "^Resp.Times:" $tempdir/status.txt | sed '/Resp.Times/{x;p;x;}'
echo -e "\nWebsite SHA1:  $p2_sha1"; echo -e "\n               ($time_stamp)\n" ; else
f_detectCDN "$tempdir/h2"
if [ $domain_enum = "false" ] ; then
f_TITLE "$tempdir/p2.html" ; fi
echo '' ; f_Long; echo -e "Website SHA1:  $p2_sha1"; echo -e "\n               ($time_stamp)"
t_dns=$(grep -E "^DNS Lookup:" $tempdir/status_raw  | sed 's/^[ \t]*//;s/[ \t]*$//')
t_tcp=$(grep -E "^TCP Hshake:"  $tempdir/status_raw | sed 's/^[ \t]*//;s/[ \t]*$//')
t_ssl=$(grep -E "^SSL Hshake:"  $tempdir/status_raw | sed 's/^[ \t]*//;s/[ \t]*$//')
t_total=$(grep -E "^Total Time:" $tempdir/status_raw | sed 's/^[ \t]*//;s/[ \t]*$//')
f_Long; echo -e "RESPONSE TIMES\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
echo -e "$t_tcp      $t_dns\n"; echo -e "$t_ssl      $t_total"
if [ $option_ping = "y" ] ; then
f_Long; f_httpPING "${eff_ip}" ; f_icmpPING "${eff_ip}" ; fi
echo ''; f_REDIR ; echo ''
if [ $option_trace = "1" ] ; then
f_Long; echo '' ; tracepath -m 22 ${eff_ip} | sed 's/^ *//' | sed '/Resume/i \\n___________________________________\n' ; echo ''
elif [ $option_trace = "2" ] ; then
f_MTR_HT "${eff_ip}"
elif [ $option_trace = "3" ] ; then
f_MTR "${eff_ip}" ; fi ; fi
f_getAppHEADERS "$tempdir/h2" > $tempdir/app_headers; f_getSecHEADERS "$tempdir/h2" > $tempdir/sec_headers; f_inspectHEADERS "$tempdir/h2"
if [ $domain_enum = "true" ]; then
echo ''; f_REDIR ; echo '' ; else
f_Long; echo -e "HOST SUMMARY" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' ; f_hostSHORT "${s}"
if [ $rep_check = "true" ] && [[ ${s} =~ $REGEX_IP4 ]] ; then
f_Long; echo "IP REPUTATION" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' ; f_IP_REPUTATION "${s}" ; fi ; echo '' ; fi
}
f_REDIR(){
echo -e "______________________________________________________________________________"
grep -E "^Connected to|SSL certificate verify|^Server:|^Via:|^HTTP" $tempdir/stat_trimmed | sed 's/ Moved//g' | sed 's/ Temporary//g' |
sed 's/Permanent //g' | sed 's/Bad //g' | sed 's/Request//g' | sed 's/Forbidden//g' | sed 's/ Temporarily//g' |
sed 's/Authentification /Auth/g' | sed 's/Required/Req/g' | sed 's/ Permanently//g' | sed 's/ Found//' | sed 's/Not//g' | sed 's/200 OK/200/g' |
sed 's/SSL certificate verify /SSL:/g' | sed 's/Redirect//g' | sed 's/Connected to/Connection/g' | sed 's/) port /:/g' |
tr '[:space:]' ' ' | sed 's/Connection/\n\n| Connection/g' | awk '{print $2,$5,$1,$3,$1,$4,$6,$7,$8,$9,$10,$11,$12,$13,$14}' |
sed 's/SSL:/| SSL: /g' | sed 's/ok./OK/g' | sed 's/HTTP/| HTTP/g' | sed 's/Server:/|/' | sed 's/Via:/| Via:/g' | tr -d '()'
}
f_detectCDN(){
local s="$*"
if grep -q -i -E "Server: AkamaiGHost|server: Akamai|server: AkamaiEdge|^x-akamai-transformed" ${s}; then
cdn="Akamai"
elif grep -q -i -E "^x-fastly-cache-status:|^fastly-restarts:" ${s}; then
cdn="Fastly"
elif grep -q -i -E "Server: Cloudflare|cf-ray:|cf-cache-status" ${s}; then
cdn="Cloudflare"
elif grep -q -i -E "OriginShieldHit|CloudFront-.*|X-Amz-Cf-Id" ${s}; then
cdn="Amazon AWS CloudFront" ; fi
if [ -n "$cdn" ] ; then
echo -e "\nCDN:           $cdn\n" ; fi
}
f_LBD(){
local s="$*" ; echo '' ; f_Long ; echo "LOAD BALANCING DETECTION" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
echo -e "\nRunning lbd... [$s]\n"
${PATH_lbd} ${s} > $tempdir/lb_detect ; sed -n '/DNS-Loadbalancing/,$p' $tempdir/lb_detect | sed 's/\[Date\]:/\[Date\]:\n/' |
sed 's/^ *//' | sed '/DNS-Loadbalancing/G' | fmt -s -w 100
}
f_icmpPING(){
local s="$*" ; timeout 5 ping -c 3 $s > $tempdir/iping
ping_stat=$(sed -n '/---/{n;p;}' $tempdir/iping | sed 's/^ *//')
rtt=$(tail -1 $tempdir/iping | awk -F'/' '{print $2,$5}' | sed 's/^ *//')
rtt2=$(tail -1 $tempdir/iping | awk -F'/' '{print $3,$6}' | sed 's/^ *//')
echo -e "\nPing [ICMP]:   $ping_stat"
echo -e "\n               $rtt ms  $rtt2 ms\n"
}
f_httpPING(){
local s="$*" ; ${PATH_httping} -t 5 ${htping_array[@]} $s > $tempdir/http_ping
connects=$(grep 'connects' $tempdir/http_ping | cut -d ' ' -f 3-)
avg=$(grep 'round-trip' $tempdir/http_ping | cut -d '=' -f 2- | cut -d '/' -f 2)
echo -e "\nPing [HTTP]:   $connects, avg: $avg ms\n"
}
f_requestTIME(){
local s="$*" ; f_Long
if [ $option_root = "y" ] ; then
sudo ${PATH_nmap} -sT -p 443 -R --resolve-all --script http-chrono,https-redirect,path-mtu ${s} 2>/dev/null > $tempdir/nmap.txt
if [ -n "$target6" ] ; then
sudo ${PATH_nmap} -6 -sT -p 443 -R --resolve-all --script http-chrono,https-redirect,path-mtu ${s} 2>/dev/null >> $tempdir/nmap.txt ; fi
echo "PATH MTU, PAGE LOADING & REFRESH TIMES" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
grep -E -i "Nmap scan report|http-chrono:|path-mtu:" $tempdir/nmap.txt | tr -d '|_' | sed 's/^ *//' | sed '/Nmap scan report/G' |
sed 's/http-chrono: //' | sed 's/Request times for /Page:          /' | sed 's/; avg:/\nTimes:         avg: /' | sed '/Page/G' |
sed '/path-mtu:/{x;p;x;}' | sed 's/path-mtu:/MTU:          /g' | sed '/MTU:/{x;p;x;}' | sed 's/PMTU == //g' |
sed 's/Nmap scan report for/\n\nHost:         /' | sed '/Host:/G' | sed 's/;min:/; min: /g' | sed 's/;max:/; max: /g'  ; echo '' ; else
${PATH_nmap} -sT -p 443 -R --resolve-all --script http-chrono,https-redirect ${s} 2>/dev/null > $tempdir/nmap.txt
if [ -n "$target6" ] ; then
${PATH_nmap} -6 -sT -p 443 -R --resolve-all --script http-chrono,https-redirect ${s} 2>/dev/null >> $tempdir/nmap.txt ; fi
echo "PAGE LOADING & REFRESH TIMES" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
grep -E -i "Nmap scan report|http-chrono:|path-mtu:" $tempdir/nmap.txt | tr -d '|_' | sed 's/^ *//' | sed '/Nmap scan report/G' |
sed 's/http-chrono: //' | sed 's/Request times for /Page:          /' | sed 's/; avg:/\nTimes:         avg: /' | sed '/Page/G' |
sed 's/path-mtu:/MTU:          /g' | sed '/MTU:/{x;p;x;}' | sed 's/PMTU == //g' | sed 's/Nmap scan report for/\n\nHost:         /' |
sed 's/;min:/; min: /g' | sed 's/;max:/; max: /g'  ; echo '' ; fi
}
f_MTR(){
local s="$*" ; echo ''
if [ $target_type = "web" ] ; then
f_Long ; echo '' ; else
f_Long; echo -e "[+]  $s  | MTR | PROTOCOL: $mtr_protocol" ; f_Long ; echo ' ' ; fi
sudo ${PATH_mtr} ${mtr_array[@]} -w -o "  L  S D  A BW  M" ${s} | sed '/HOST:/G' > $tempdir/mtr.txt
cat $tempdir/mtr.txt; f_Shorter;  echo -e "Snt = packages sent; Wrst = worst RTT in ms; \nJavg = average jitter" ; echo ''
}
f_MTR_HT(){
local s="$*"; f_Long; echo -e "$target MTR (ICMP)"; echo -e "$(date)\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
curl -s https://api.hackertarget.com/mtr/?q=${s}${api_key_ht}; echo -e "\n Source > hackertarget.com"
}

#********************** HTTP HEADERS - DUMP & ANALYSIS ***********************
f_HEADERS(){
local s="$*" ; echo ''; f_Long ; echo -e "[+] $s | HTTP HEADERS | $(date)" ; f_Long ; echo ''
cat $tempdir/headers | sed 's/Content-Security-Policy:/\nContent-Security-Policy:\n\n/g' | sed 's/content-security-policy:/\ncontent-security-policy:\n\n/g' |
sed 's/permissions-policy:/\npermissions-policy:\n\n/g' | sed 's/^ *//' | fmt -w 120 -s ; echo ''
}
f_getAppHEADERS(){
local s="$*" ; grep -E -a -i "^server:" ${s} | cut -d ':' -f 2- | sed 's/^ *//' | tr [:lower:] [:upper:] | sort -uV
grep -E -a -i "server-instance" ${s} | tail -1 ; grep -E -a -i "^via:" ${s} | tail -1
grep -E -a -i "^via proxy:" ${s} | tail -1 ; grep -E -a -i -m 1  "^X-Squid:" ${s} | tail -1
grep -E -a -i -m 1  "^X-Varnish:" ${s} | tail -1 ; grep -E -a -i "^x-redirect-by:" ${s} | sort -u
grep -E -a -i "^X-Server-Name:" ${s} | tail -1  ; grep -E -a -i "^x-forwarded-by:" ${s} | tail -1
grep -E -a -i "^x-client-location:" ${s} | tail -1; grep -E -a -i "*.forwarded:" ${s} | tail -1
grep -E -a -i "^x-location:" ${s} | tail -1; grep -E -a -i "x-akamai-transformed" ${s} | tail -1
grep -E -a -i -m 1 "^x-fastly-cache-status:|^fastly-restarts:" ${s}
grep -E -a -i "cf-cache-status" ${s} | tail -1; grep -E -a -i "cf-ray:" ${s} | tail -1
grep -E -a -i "mpulse_cdn_cache:" ${s} | tail -1; grep -E -a -i "mpulse_cdn_cache:" ${s}
grep -E -a -i "OriginShieldHit" ${s} | tail -1; grep -E -a -i "CloudFront-.*" ${s} | tail -1
grep -E -a -i "X-Amz-Cf-Id" ${s} | tail -1 ; grep -E -a -i "^x-pass:" ${s}  | tail -1
grep -E -a -i "^x-pass-why:" ${s} | tail -1 ; grep -s -i "^x-proxy-cache:" ${s} | tail -1
grep -E -a -i "^x-robots-tag:" ${s} | tail -1; grep -s -E -i "^X-Served-By" ${s} | tail -1
grep -E -m 2 "HIT|MISS" ${s}; grep -E -a -i "^X-UA-Compatible:" ${s} | tail -1
grep -E -a -i "^vary:" ${s} | tail -1 ; grep -E -a -i -m 1 "^X-AspNet-Version" ${s}
grep -E -a -i -m 1 "^Liferay-Portal" ${s} ; grep -E -a -i -m 1 "^X-TYPO3-.*" ${s}
grep -E -a -i -m 1 "^X-OWA-Version" ${s}  ; grep -E -a -i -m 1 "^X-Generator:" ${s}
grep -E -a -i -m 1 "^x-environment:" ${s} ; grep -E -a -i -m 1 "^X-Powered-By:" ${s}
grep -E -a -i -m 1 "^Powered-By:" ${s} ; grep -E -a -i -m 1 "^X-Version:" ${s}
grep -E -a -i -m 1 "Debian" ${s}; grep -E -a -i -m 1 "Ubuntu" ${s} ; grep -E -a -i -m 1 "linux" ${s}
grep -E -a -i -m 1 "solaris" ${s} ; grep -E -a -i -m 1 "SUSE" ${s}
grep -E -a -i -m 1 "Red Hat|RHEL" ${s} ; grep -E -a -i -m 1 "CentOS" ${s}
grep -E -a -i "win32" ${s} | sort -u ; grep -E -a -i "win64" ${s} | sort -u
grep -E -a -i "^link:" ${s} | sort -u ; echo ''
}
f_getSecHEADERS(){
local s="$*"
c_pol=$(grep -E -o "default-src|font-src|frame-src|img-src|style-src|frame-ancestors|media-src" ${s}  | sort -u | tr '[:space:]' ' ' ; echo '')
grep -s -E -i "^access-control-allow-origin:" ${s} | tail -1 ; grep -s -a -E -i "^access-control-allow-headers:" ${s} | tail -1
grep -s -a -E -i "^access-control-expose-headers:" ${s} | tail -1; grep -s -a -E -i "^allow:" ${s}
grep -s -a -E -i "^cache-control:" ${s} | tail -1; grep -s -a -E -i "^clear-site-data " ${s} | tail -1
if [ -z "$c_pol" ] ; then
grep -m 1 -i -o "^Content-Security-Policy" ${s}; fi
grep -s -a -E -i -o "^cross-origin-embedder-policy " ${s} | tail -1
grep -s -a -E -i -o "^cross-origin-opener-policy" ${s} | tail -1
grep -s -a -E -i -o "^cross-origin-resource-policy" ${s} | tail -1
grep -s -E -i "^expect-ct:" ${s} | tail -1; grep -i -o "^feature-policy" ${s} | tail -1
grep -s -E -i -o -m 1 "^P3P" ${s}; grep -s -i -E -o -m 1 "^permissions-policy" ${s}
grep -s -E -i "^referrer-policy:" ${s} | tail -1; grep -s -E -i "^Strict-Transport-Security:" ${s} | tail -1
grep -s -E -i "^X-Content-Type-Options:" ${s} | tail -1; grep -s -E -i "^X-Frame-Options:" ${s} | tail -1;
grep -s -E -i "^X-Xss-Protection:" ${s} | tail -1; grep -s -E -i -o "^X-WebKit-CSP" ${s} | tail -1;
grep -E -i -o "^X-Permitted-Cross-Domain-Policies" ${s} | tail -1
if [ -n "$c_pol" ] ; then
echo '' ;  grep -m 1 -i -o "^Content-Security-Policy:" ${s} ; echo "$c_pol"; fi
cookie_count=$(grep -s -i -o "^set-cookie:" ${s} | wc -w)
if [ $cookie_count != "0" ] ; then
path_flag=$(grep -s -i "^set-cookie:" ${s} | grep -s -i -o -a "path=*" | wc -w)
httponly=$(grep -s -i "^set-cookie:" ${s} | grep -s -i -o -a "httponly" | wc -w)
secure_flag=$(grep -s -i "^set-cookie:" ${s} | grep -s -i -o -a 'secure' | wc -w)
echo -e "\nCookies: $cookie_count  >  Flags:  HttpOnly: ${httponly}x | Path: ${path_flag}x | Secure: ${secure_flag}x" ; fi
}
f_inspectHEADERS(){
local s="$*"; f_Long
echo -e "HEADERS  (APP/REV.PROXY/OTHER)" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
links=$(grep -E -i "link:" ${s} | grep 'alternate' | cut -d '<' -f 2- | cut -d '>' -f 1 | sed 's/^ *//' | tr -d ' ')
if [ -n "$links" ] ; then
grep -E -i "^location:" $tempdir/h2 | tail -1 | awk '{print $NF}'
for l in $(echo "$links" | sort -u); do
curl -sILk -m 5 ${l} >> $tempdir/h3
echo -e "\n$l\n\n" >> $tempdir/sec_headers_alternate
echo -e "$l\n\n" >> $tempdir/app_headers_alternate
grep -E -i -s -a "^HTTP/.*" $tempdir/h3 | tail -1 >> $tempdir/app_headers_alternate
f_getAppHEADERS "$tempdir/h3" >> $tempdir/app_headers_alternate
f_getSecHEADERS "$tempdir/h3" >> $tempdir/sec_headers_alternate ; done ; fi
cat $tempdir/app_headers ; echo ''
if [ -f $tempdir/app_headers_alternate ] ; then
if [[ $(cat $tempdir/app_headers_alternate | wc -l) -gt 3 ]] ; then
grep -E -a -i -v "^link:" $tempdir/app_headers_alternate; fi ; fi
f_Long; echo -e "SECURITY HEADERS\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
if [ -n "$links" ] ; then
grep -E -i "^location:" $tempdir/h2 | tail -1 | awk '{print $NF}'; echo  '' ; fi
if [[ $(cat $tempdir/sec_headers | wc -w) -lt 2 ]] ; then
echo -e "Not set / not forwarded by another service (e.g. CDN)" ; else
cat $tempdir/sec_headers ; echo '' ; fi
if [ -f $tempdir/sec_headers_alternate ] ; then
if [[ $(cat $tempdir/sec_headers_alternate | wc -l) -lt 3 ]] ; then
echo -e "\nNot set / not forwarded by another service (e.g. CDN)\n" ; else
cat $tempdir/sec_headers_alternate; fi ; fi
}

#********************** DOMAIN STATUS SUMMARY, WHOIS STATUS, DNS FORWARD CHAIN ***********************
f_whoisSTATUS(){
local s="$*"
if echo $s | grep -q -E "\.edu\.|\.co\.|\.org.|\.gov\."; then
whois_query=$(echo $s | sed 's/http:\/\///' | sed 's/https:\/\///' | cut -d '/' -f 1 | rev | cut -d '.' -f 1,2,3 | rev) ; else
whois_query=$(echo $s | sed 's/http:\/\///' | sed 's/https:\/\///' | cut -d '/' -f 1 | rev | cut -d '.' -f 1,2 | rev) ; fi
whois $whois_query | sed '/please/d' | sed '/%/d' | sed '/REDACTED/d' | sed '/for more/d' | sed 's/^ *//' > $tempdir/whois_domain
if echo $s | grep -q -E "\.jp"; then
sed -n '/Domain Information:/,$p' $tempdir/whois_domain ; else
whois_mail=$(grep -E -i -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/whois_domain | sort -uf | head -2 | tr '[:space:]' ' '; echo '')
if [ -n "$whois_mail" ] ; then
if [[ $(echo "$whois_mail" | wc -w) -gt 1 ]]; then
echo -e "\n[@]:  $whois_mail" > $tempdir/whoisd; echo -e "____\n\n" >> $tempdir/whoisd; else
echo -e "[@]:  $whois_mail" > $tempdir/whoisd; echo -e "____\n" >> $tempdir/whoisd ; fi ; else
echo '' > $tempdir/whoisd; fi
grep -E -a -i "^domain:|^domain name:" $tempdir/whois_domain | head -1 >> $tempdir/whoisd
grep -i -E -m 1 -A 1 "^domain:|^domain name:" $tempdir/whois_domain | tail -1 | grep -v ':' >> $tempdir/whoisd
grep -E -a -i -m 2 "^status:|^domain status:|^registered" $tempdir/whois_domain | sort -u | awk -F'https:' '{print $1}' >> $tempdir/whoisd
grep -i -E "expiry date|expires" $tempdir/whois_domain > $tempdir/whois_temp
grep -E -a -i -m 1 "^updated:|^changed:|update" $tempdir/whois_domain >> $tempdir/whois_domain_temp
grep -E -a -i "Re-registration" $tempdir/whois_domain | head -1 >> $tempdir/whois_domain_temp
cat $tempdir/whois_domain_temp | sort -u >> $tempdir/whoisd
grep -w -a -i -m 1 "country:" $tempdir/whois_domain >> $tempdir/whoisd
grep -E -a -i -m 2 "^Company English Name|Company Chinese Name:" $tempdir/whois_domain >> $tempdir/whoisd
grep -E -a -m 1 "^admin-c:" $tempdir/whois_domain >> $tempdir/whoisd
grep -E -a -m 1 -A 5 "^Registrar:" $tempdir/whois_domain | grep -E -a -i "registrar:|city:|phone:" |
sort -u >> $tempdir/whoisd
grep -E -a -m 1 -A 6 "^registrar:" $tempdir/whois_domain | grep -E -a -i "registrar:|city:|phone:" |
sort -u >> $tempdir/whoisd
grep -E -a -m 1 -A 6 "^registrant:" $tempdir/whois_domain | grep -E -a -i "registrant:|city:|phone:" |
sort -u >> $tempdir/whoisd
grep -E -a -m 1 -A 6 "^Company name:" $tempdir/whois_domain | grep -E -a -i "registrant:|city:|phone:" |
sort -u >> $tempdir/whoisd
grep -E -i "^nameserver:|^name server:|^nserver:" $tempdir/whois_domain >> $tempdir/whoisd
grep -E -A 10 "^nameservers:|^NAMESERVERS" $tempdir/whois_domain |
grep -E -i -o "nameservers|\b[A-Za-z0-9]+[-_\.]+[A-Za-z0-9]+\.[A-Za-z]{2,6}\b" >> $tempdir/whoisd
grep -E -i -m 1 "^dnssec:" $tempdir/whois_domain | tail -1 >> $tempdir/whoisd; cat $tempdir/whoisd
if [ -f $tempdir/whois_domain_temp ] ; then
rm $tempdir/whois_domain_temp ; fi ; fi; echo ''
}
f_dnsFOR_CHAIN(){
local s="$*" ; auth_ns='' ; curl -s "https://stat.ripe.net/data/dns-chain/data.json?resource=${s}" > $tempdir/chain.json
auth_ns=$(jq -r '.data.authoritative_nameservers[]' $tempdir/chain.json | sed '/null/d')
if [ -n "$auth_ns" ] ; then
export auth_ns; jq -r '.data.forward_nodes' $tempdir/chain.json | tr -d '{,"}' | sed 's/^ *//' | sed '/^$/d' | sed 's/\]//g' |
tr -d '[' > $tempdir/chain.txt; cat $tempdir/chain.txt
if [ $domain_enum = "false" ] ; then
egrep -s -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/chain.txt | sort -uV > $tempdir/addresses
jq -r '.data.authoritative_nameservers[]' $tempdir/chain.json >> $tempdir/authns
jq -r '.data.authoritative_nameservers[]' $tempdir/chain.json | sort -V | tr '[:space:]' ' ' | fmt -s -w 80
echo '' ; fi ; fi
}
f_DNSWhois_STATUS(){
local s="$*" ; f_Long
if [ $domain_enum = "true" ] ; then
echo -e "WHOIS STATUS, DNS CHAIN" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; else
echo -e "WHOIS STATUS, DNS CHAIN" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; fi
f_whoisSTATUS "${s}" ; echo ''; f_dnsFOR_CHAIN "${s}"
}
f_domainSTATUS(){
local s="$*" ; echo ''
f_Long; echo "[+] $s  | DOMAIN STATUS SUMMARY"; f_Long ; option_authns="true"
echo -e "WEBSITE STATUS" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
if [ $option_connect = "0" ] ; then
eff_url=$(cut -s -d ']' -f 1 $tempdir/ww.txt | sed 's/\[/ /' | tail -1)
echo '' ; cut -s -d ']' -f 1 $tempdir/ww.txt | sed 's/\[/ /' | sed G; else
eff_url=$(grep "^URL:" $tempdir/response | cut -d ':' -f 2- | sed 's/^ *//')
status=$(grep 'Status:' $tempdir/response | cut -d ':' -f 2- | sed 's/^ *//')
verify=$(grep -s -m 1 'SSL certificate verify' $tempdir/curl_trimmed | rev | cut -d ' ' -f 1 | rev | tr -d '.')
echo -e "\nWebsite:      $eff_url" ; echo -e "Status:       $status"; echo -e "SSL:          $verify\n" ; fi
target_hostname=$(echo $eff_url | sed 's/http:\/\///' | sed 's/https:\/\///' | cut -d '/' -f 1)
if echo $eff_url | grep -q -E "\.edu\.|\.co\.|\.org.|\.gov\."; then
target_url_dom=$(echo $eff_url | sed 's/http:\/\///' | sed 's/https:\/\///' | cut -d '/' -f 1 | rev | cut -d '.' -f 1,2,3 | rev) ; else
target_url_dom=$(echo $eff_url | sed 's/http:\/\///' | sed 's/https:\/\///' | cut -d '/' -f 1 | rev | cut -d '.' -f 1,2 | rev) ; fi
f_DNSWhois_STATUS "${s}" > $tempdir/domain_status
jq -r '.data.authoritative_nameservers[]' $tempdir/chain.json | sort -V | tr '[:space:]' ' ' | fmt -s -w 80 >> $tempdir/domain_status
echo '' >> $tempdir/domain_status
if ! [ "$s" = "$target_url_dom" ] ; then
f_DNSWhois_STATUS "${target_url_dom}" >> $tempdir/domain_status ; fi
if ! [ "$s" = "$target_hostname" ] && ! [ "$target_hostname" = "$target_url_dom" ] ; then
f_dnsFOR_CHAIN "${target_hostname}" >> $tempdir/domain_status ; fi
jq -r '.data.authoritative_nameservers[]' $tempdir/chain.json | sort -V | tr '[:space:]' ' ' | fmt -s -w 80 >> $tempdir/domain_status
echo '' >> $tempdir/domain_status; cat $tempdir/domain_status
}
#********************** GENERAL WHOIS INFORMATION ***********************
f_getWHOIS(){
local s="$*" ; whois_ip=$(echo $s | cut -d '/' -f 1); f_getRIR "${s}"
if [ $rir = "arin" ] ; then
whois -h whois.arin.net $s | sed '/^#/d' | sed '/^$/d' > $tempdir/whois.txt
elif [ $rir = "lacnic" ] ; then
whois -h whois.lacnic.net $s > $tempdir/whois.txt ; else
whois -h whois.$rir.net -- "-B ${s}" > $tempdir/whois.txt ; fi
export rir
}
f_WHOIS_OUT(){
local s="$*"
if [ $rir = "lacnic" ] ; then
netabu=$(grep -E -o -m 2 "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/whois.txt | sort -u -V | tr '[:space:]' ' ' ; echo ''); else
netabu=$(grep -E -i -m 1 "^OrgAbuseEmail:|^% Abuse|^abuse-mailbox:|^e-mail:" $tempdir/whois.txt |
grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b") ; fi
echo -e "\n" ; f_Long ; echo -e "WHOIS  |  $s  |  SERVER:  whois.$rir.net" ; f_Long; echo -e "[@]: $netabu"; echo -e "____\n"
if [ $rir = "lacnic" ] ; then
cat $tempdir/whois.txt | sed '/inetrev:/a \\n__________________________________________________\n' ; else
cat $tempdir/whois.txt | grep -E -v "^admin-c:|^mnt-by:|^tech-c:|^fax-no:|^remarks:|^source:" | sed '/^%/d' | sed '/^$/d' |
sed '/NetRange:/{x;p;x;}' | sed '/CIDR:/G' | sed '/Organization:/{x;p;x;}' | sed '/NetName:/{x;p;x;}' | sed '/Updated:/G' |
sed '/OrgAbuseHandle:/i \\n__________________________________________________\n\n' |
sed '/route:/i \\n__________________________________________________\n' | sed '/route6:/i \\n__________________________________________________\n' |
sed '/person:/i \\n__________________________________________________\n' | sed '/role:/i \\n__________________________________________________\n' |
sed '/OrgName:/i \\n__________________________________________________\n' | sed '/netname:/G' |
sed '/OrgNOCHandle:/i \\n__________________________________________________\n' | sed '/^Country:/G' | sed '/^person:/G' | sed '/^role:/G' |
sed '/organisation:/i \\n__________________________________________________\n' | sed '/^org-name/G' | sed '/^route:/G' | sed '/^route6:/G' |
sed '/OrgTechHandle:/i \\n__________________________________________________\n' ; fi
if ! [ $rir = "lacnic" ] && ! [ $rir = "arin" ] ; then
grep -E "^admin-c:|^mnt-by:|^tech-c:|^abuse-c:|^mnt-lower:" $tempdir/whois.txt |  tr ':' ';'  | tr -d ' '  > $tempdir/hdl.list
echo -e "__________________________________________________\n" ; echo -e "* $rir OBJECT HANDLES\n\n"
cat $tempdir/hdl.list | sort -uV ; echo -e "\n__________________________________________________\n"
echo -e "* CONTACTS\n\n" ; grep -s -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/whois.txt | sort -f -u
if [[ $(grep -s -w -c '^remarks:' $tempdir/whois.txt ) -gt "0" ]] ; then
echo -e "\n__________________________________________________\n"
echo -e "* REMARKS\n\n" ; grep -E "^remarks:" $tempdir/whois.txt ; fi ; fi
}
f_getORGNAME(){
local s="$*"
org_whois=$(grep -E -i -m 1 "^organization:|^org-name:|^owner:" $s | cut -d ':' -f 2- | sed 's/^ *//')
descr=$(grep -E -i -m 1 "^descr:" $s | cut -d ':' -f 2- | sed 's/^ *//')
if ! [ $target_type = "net" ]; then
org=$(jq -r '.org' $tempdir/geo.json) ; else
org='' ; fi
if [ -n "$org_whois" ] ; then
if [ $rir = "arin" ] ; then
org_cc=$(grep -s -E -m 1 "^Country:" $s | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
org_city=$(grep -s -E -m 1 "^City:" $s | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
orgname=$(grep -s -E -m 1 "^Organization:" $s | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
org_out="$orgname,  $org_city, $org_cc"
elif [ $rir = "lacnic" ] ; then
org_cc=$(grep -E -m 1 "^country:" $s | cut -d ':' -f 2 | sed 's/^ *//')
orgid=$(grep -E -m 1 "^owner-c:" $s | cut -d ':' -f 2 | sed 's/^ *//')
orgname=$(grep -a -E -m 1 "^owner:" $s | cut -d ':' -f 2- | sed 's/^ *//')
org_out="$orgname, $org_cc  ($orgid)"; else
if [[ $(sed -e '/./{H;$!d;}' -e 'x;/organisation:/!d' $s | grep -s -w -c '^country:') -gt "0" ]] ; then
org_cc=$(sed -e '/./{H;$!d;}' -e 'x;/organisation:/!d' $s | grep -E -m 1 "^country:" | head -1 | cut -d ':' -f 2- | sed 's/^ *//'); else
org_cc=$(sed -e '/./{H;$!d;}' -e 'x;/organisation:/!d' $s | grep -E "^address:" | tail -1 | cut -d ':' -f 2- | sed 's/^ *//'); fi
orgid=$(grep -s -a -E "^organisation:" $s | cut -d ':' -f 2- | sed 's/^ *//' | head -1)
orgname=$(grep -s -a -E "^org-name:" $s | cut -d ':' -f 2- | sed 's/^ *//' | head -1)
orgtype=$(grep -E "^org-type:" $s | head -1 | cut -d ':' -f 2- | sed 's/^ *//')
if [ -n "$orgtype" ] ; then
org_out="$orgname, $org_cc  ($orgid, $orgtype)" ; else
org_out="$orgname, $org_cc  ($orgid)"; fi ; fi
echo -e "\nOrg:         $org_out" ; else
if ! [ $target_type = "net" ] && [ -n "$descr" ] ; then
echo -e "\nNetDescr:    $descr"
elif ! [ $target_type = "net" ] && [ -n "$org" ] ; then
echo -e "\nOrg:         $org" ; fi ; fi
if [ $domain_enum = "false" ] ; then
echo '' ; fi
}
f_ORG(){
local s="$*"
if [[ $(grep -s -c -E "^OrgName:|^Organization:" ${s}) -gt "0" ]] ; then
f_ARIN_ORG "$s"
elif [[ $(grep -s -c -E "^organisation:" ${s}) -gt "0" ]] ; then
org_id=$(grep -E -a "^organisation:" ${s} | head -1 | awk '{print $NF}' | sed 's/^ *//')
org_type=$(grep -E "^org-type:" $s | head -1 | cut -d ':' -f 2- | sed 's/^ *//'); f_Long
if ! [ $option_detail = "2" ] ; then
echo -e "ORG: $org_id" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
sed -n '/organisation:/,/organisation:/p' ${s} | grep -E -a -m 1 -A 12 "^org-name" > $tempdir/temp
o_name=$(grep -E -a -m 1 "^org-name:" $tempdir/temp | cut -d ':' -f 2- | sed 's/^ *//')
o_addr=$(grep -E -a "^address:" $tempdir/temp | cut -d ':' -f 2- | sed 's/^ *//' | tr '[:space:]' ' ')
o_ph=$(grep -E -a -m 1 "^phone:" $tempdir/temp | cut -d ':' -f 2- | sed 's/^ *//')
if [ $target_type = "other" ] ; then
echo -e "$o_name  $o_ph" ; else
echo -e "$o_name"; fi; echo "$org_type" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
if ! [ $target_type = "other" ] ; then
echo -e "$o_ph\n"; fi ; echo -e "$o_addr\n" ; else
echo -e "ORG: $org_id, $org_type" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; whois -h whois.$rir.net -- "-B $org_id" > $tempdir/org_whois
sed -n '/organisation:/,/organisation:/p' $tempdir/org_whois | grep -E -a -s "^org-name:|^role:|^person:|^address:|^phone:|^e-mail:" |
sed '/org-name:/a nnn' | sed '/phone:/i nnn' | sed '/person:/i nnn' | sed '/role:/i nnn' | sed '/mntner:/i nnn' | sed '/e-mail:/i nnn' |
cut -d ':' -f 2- | sed 's/^ *//' | tr '[:space:]' ' ' | sed 's/nnn /\n\n/g' ; echo '' ; fi; fi
}
f_ADMIN_C(){
local admin="$*"; echo -e "ADMIN-C: $admin\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
if [ $option_detail = "1" ] || [ $option_detail = "3" ]; then
whois -h whois.$rir.net -- "-F -r $admin" | tr -d '*' | sed 's/^ *//' > $tempdir/ac
ad_name=$(grep -E -a "^pn:|^ro:" $tempdir/ac | cut -d ':' -f 2- | sed 's/^ *//' | tr '[:space:]' ' ')
ad_phone=$(grep -E -a "^ph:" $tempdir/ac | cut -d ':' -f 2- | sed 's/^ *//' | sort -u | tr '[:space:]' ' ')
ad_address=$(grep -E -a "^ad:|^\+" $tempdir/ac | cut -d ':' -f 2- | sed 's/^+ //' | sed 's/^ *//' | tr '[:space:]' ' ')
echo -e "$ad_name   $ad_phone\n"; echo -e "$ad_address\n" ; else
whois -h whois.$rir.net -- "-B $admin" > $tempdir/ac
if [[ $(grep -s -w -c '^role:' $tempdir/ac) -gt "0" ]] ; then
sed -e '/./{H;$!d;}' -e 'x;/role:/!d' $tempdir/ac | grep -E -a "^role:|^address:|^phone:|^nic-hdl:" |
sed '/role:/a nnn' | sed '/role:/i nnn' | sed '/phone:/i nnn' | sed '/e-mail:/i nnn' | sed '/nic-hdl:/i nnn' |
sed '/nic-hdl:/a nnn' | cut -d ':' -f 2- | sed 's/^ *//' | tr '[:space:]' ' ' | sed 's/nnn /\n/g' ; echo '' ; fi
if [[ $(grep -s -w -c '^person:' $tempdir/ac) -gt "0" ]] ; then
sed -e '/./{H;$!d;}' -e 'x;/person:/!d' $tempdir/ac | grep -E -a "^person:|^address:|^phone:|^e-mail:|^nic-hdl:" |
sed '/person:/a nnn' | sed '/person:/i nnn' | sed '/phone:/i nnn' | sed '/e-mail:/i nnn' | sed '/nic-hdl:/i nnn' |
sed '/nic-hdl:/a nnn' | cut -d ':' -f 2- | sed 's/^ *//' | tr '[:space:]' ' ' | sed 's/nnn /\n/g' ; echo ''; fi; fi
}

#********************** HOST INFORMATION ***********************
f_geoWHOIS(){
local s="$*" ; as='' ; pfx=''; resource='' ; curl -s -m 5 "http://ip-api.com/json/${s}?fields=54750987" > $tempdir/geo.json
curl -s "https://stat.ripe.net/data/network-info/data.json?resource=${s}" > $tempdir/net.json
as=$(jq -r '.data.asns[0]' $tempdir/net.json); pfx=$(jq -r '.data.prefix' $tempdir/net.json) 
if [ $domain_enum = "true" ] && ! [[ ${s} =~ $REGEX_IP4 ]] ; then
echo $pfx >> $tempdir/v6_prefixes; fi
if [ -n "$as" ] ; then
export as ; fi ; f_getRIR "${s}"
if [ $target_type = "hop" ] ; then
f_PREFIX "${pfx}" > $tempdir/prefix_status ; fi
if [ $rir = "lacnic" ] || [ $rir = "arin" ] ; then
timeout 7 whois -h whois.$rir.net $s > $tempdir/whois
elif [ $rir = "ripe" ] ; then
if ! [[ ${s} =~ $REGEX_IP4 ]] ; then
timeout 7 whois -h whois.ripe.net -- "--no-personal $s" > $tempdir/whois ; else
if [ $target_type = "default" ] ; then
curl -s -m 7 "https://stat.ripe.net/data/address-space-usage/data.json?resource=${s}" > $tempdir/space_usage.json
resource=$(jq -r '.data.resource' $tempdir/space_usage.json)
if [ -n "$resource" ] ; then
timeout 7 whois -h whois.ripe.net -- "--no-personal $resource" > $tempdir/whois; else
timeout 7 whois -h whois.ripe.net -- "--no-personal $s" > $tempdir/whois ; fi; else
timeout 7 whois -h whois.ripe.net -- "--no-personal $s" > $tempdir/whois ; fi;  fi ; else
timeout 7 whois -h whois.$rir.net -- "--no-personal $s" > $tempdir/whois; fi
if [[ $(grep -s -E -i -c "^netname:|^net-name:|^na:|^inetrev:" $tempdir/whois) = 0 ]] ; then
timeout 10 whois -h whois.pwhois.org type=all $s > $tempdir/whois
pfx=$(grep -E "^Prefix:" $tempdir/whois | awk '{print $NF}' | sed 's/^[ \t]*//;s/[ \t]*$//')
as=$(grep -E "^Origin-AS:" $tempdir/whois | awk '{print $NF}' | sed 's/^[ \t]*//;s/[ \t]*$//') ; else
curl -s -m 7 "https://stat.ripe.net/data/network-info/data.json?resource=${s}" > $tempdir/net.json
as=$(jq -r '.data.asns[0]' $tempdir/net.json | sed '/null/d'); pfx=$(jq -r '.data.prefix' $tempdir/net.json); fi
if [ -n "$as" ] ; then
export pfx; export as
if [ $target_type = "hop" ] ; then
if [[ $(grep -s -E -i -c "^netname:|^net-name:|^na:|^inetrev:" $tempdir/whois) = 0 ]] ; then
f_PREFIX "${pfx}" > $tempdir/prefix_status ; fi ; else
if ! [ $target_type = "default" ] ; then
asorg=$(curl -s -m 5 "https://stat.ripe.net/data/as-overview/data.json?resource=AS${as}" | jq -r '.data.holder')
if [ $domain_enum = "true" ] && [ $target_type = "dnsrec" ] ; then
echo -e "\nPrefix:      $pfx | AS $as - $asorg" > $tempdir/prefix_status; else
curl -m 5 -s "https://stat.ripe.net/data/rpki-validation/data.json?resource=$as&prefix=$pfx" > $tempdir/rpki.json
rpki_status=$(jq -r '.data.status' $tempdir/rpki.json)
echo -e "\nPrefix:      $pfx | ROA: $rpki_status | AS $as - $asorg"  > $tempdir/prefix_status; fi ; fi ; fi ; fi
}
f_ABUSE_C(){
local s="$*" ; netname='' ; range='' ; abx='' ; net_ip=$(echo $s | cut -d '/' -f 1)
netname=$(grep -E -i -m 1 "^netname:|^Net-Name:|^na:|^inetrev" $tempdir/whois | cut -d ':' -f 2- | sed 's/^ *//')
range=$(grep -E -i -m 1 "^inetnum|^inet6num:|^netrange:|^net-range|^in:|^i6:" $tempdir/whois | cut -d ' ' -f 2- | sed 's/^ *//')
ctry=$(grep -E -i -m 1 "^country:|^cy:" $tempdir/whois | cut -d ':' -f 2- | sed 's/^ *//' | tr [:lower:] [:upper:])
abx=$(grep -E -a -s -m 1 "^OrgAbuseEmail:|^% Abuse|^abuse-mailbox:|^e-mail:|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/whois |
grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b") 
if [ -z "$abx" ] ; then
abx=$(grep -E -o -m 1 "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/whois); fi
if [ $rir = "lacnic" ] ; then
echo -e "[@]:  $abx" ; else
if [ $target_type = "default" ] ; then
if [ -n "$abx" ] ; then
echo -e "[@]:  $abx | $netname:  $range" ; else
echo -e "NET:  $netname:  $range" ; fi ; else
if [ $domain_enum = "true" ] && [[ ${net_ip} =~ $REGEX_IP4 ]] ; then
range_trimmed=$(echo $range | tr -d ' ')
net_cidr=$(ipcalc -r ${range_trimmed} | sed '/deaggregate/d' | sed '/^$/d')
if [[ $(echo "$net_cidr" | wc -l) -eq 1 ]] ; then
echo -e "[@]:  $abx | $netname ($ctry): $net_cidr" ; else
echo -e "[@]:  $abx | NET: $netname ($ctry)" ; fi; else
if [ -n "$abx" ] ; then
echo -e "[@]:  $abx | $netname ($ctry):  $range" ; else
echo -e "NET:  $netname ($ctry):  $range" ; fi ; fi ; fi ; fi ; echo -e "____\n" ; export abx
}
f_hostINFO(){
local s="$*"; orgname=''; offset=$(($(jq -r '.offset' $tempdir/geo.json) / 3600)); regio=$(jq -r '.regionName' $tempdir/geo.json)
if [ -n "$as" ]; then
echo -e "\nGeo:         $regio, $(jq -r '.country' $tempdir/geo.json) (UTC ${offset}h)" ; fi
if [ $target_type = "hop" ] || [ $target_type = "other" ]; then
isp=$(jq -r '.isp' $tempdir/geo.json); hosting=$(jq -r '.hosting' $tempdir/geo.json)
if [[ ${s} =~ $REGEX_IP4 ]] ; then
echo -e "\nISP:         $isp  | Hosting: $hosting | $(f_TOR1 "${s}")" ; else
echo -e "\nISP:         $isp  | Hosting: $hosting"; fi ; fi
if ! [[ ${s} =~ $REGEX_IP4 ]] ; then
ipv6_info=$(${PATH_nmap} -6 -sn -Pn $s --script address-info.nse 2>/dev/null | grep -E -A 1 "\||\|_|ISATAP" | sed '/--/d' | sed '/address-info:/d' |
tr -d '|_' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' | sed 's/MAC address:/MAC/' | tr '[:space:]' ' '; echo '')
if [ -n "$ipv6_info" ]; then
echo -e "\nIPv6-Info:   $ipv6_info\n" ; fi ; fi 
f_getORGNAME "$tempdir/whois" ; cat $tempdir/prefix_status
}
f_hostDEFAULT(){
echo ''; local s="$*" ; orgname='' ; assign=''; suballoc=''; resource=''; parent=''; f_geoWHOIS "${s}"
regio=$(jq -r '.regionName' $tempdir/geo.json); offset=$(($(jq -r '.offset' $tempdir/geo.json) / 3600))
org=$(jq -r '.org' $tempdir/geo.json); isp=$(jq -r '.isp' $tempdir/geo.json); whois_reg=$(echo $rir | tr [:lower:] [:upper:])
hosting=$(jq -r '.hosting' $tempdir/geo.json); mobile=$(jq -r '.mobile' $tempdir/geo.json); geo_cc=$(jq -r '.countryCode' $tempdir/geo.json)
f_Long; echo "[+] $s | $geo_cc | $whois_reg | AS $as "; f_Long; f_ABUSE_C "${s}"
if [ -n "$as" ]; then
echo -e "\nGeo:         $regio, $(jq -r '.country' $tempdir/geo.json) (UTC ${offset}h)" ; fi
if ! [[ ${s} =~ $REGEX_IP4 ]] ; then
ipv6_info=$(nmap -6 -sn -Pn $s --script address-info.nse 2>/dev/null | grep -E -A 1 "\||\|_|ISATAP" | sed '/--/d' | sed '/address-info:/d' |
tr -d '|_' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' | sed 's/MAC address:/MAC/' | tr '[:space:]' ' '; echo '')
echo -e "\nISP:         $isp  | Mobile: $mobile | Hosting: $hosting"
if [ -n "$ipv6_info" ]; then
echo -e "\nIPv6-Info:   $ipv6_info\n" ; fi ; else
if [ $option_bl = "y" ] ; then
curl -s "https://isc.sans.edu/api/ip/${s}?json" > $tempdir/iscip.json
ip_num=$(jq -r '.ip.number?' $tempdir/iscip.json)
if [ -n "$ip_num" ] ; then
cloud_service=$(jq -r '.ip.cloud' $tempdir/iscip.json | sed 's/null/false/')
export cloud_service; cloud="| Cloud: $cloud_service"; else
cloud='' ; fi ; fi
echo -e "\n             Mobile: $mobile | $(f_TOR1 "${s}") | Hosting: $hosting $cloud\n"
echo -e "ISP:         $isp"; fi; f_getORGNAME "$tempdir/whois"
if ! [ $rir = "lacnic" ] && ! [ $option_type = "3" ] ; then
f_dnsFOR_CHAIN "${s}" > $tempdir/dns_chain
if [ -n "$auth_ns" ]; then
echo '' ; f_Long; echo -e "DNS" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
cat $tempdir/dns_chain ; else
if [ $rir = "ripe" ] ; then
echo '' ; f_Long; echo -e "REV.DNS DELEGATION" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
f_DELEGATION "${s}" > $tempdir/rdnszone; cat $tempdir/rdnszone | sed '/./,$!d' ; fi ; fi; fi
if  [ $option_banners = "true" ] ; then
f_BANNERS "${s}" ; echo '' ; fi
if  [ $option_bl = "y" ] ; then
f_Long; echo -e "IP REPUTATION\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' ; f_IP_REPUTATION "${s}" ; echo '' ; fi
if [ $rir = "lacnic" ] ; then
echo '' ; f_lacnicWHOIS "${s}" ; else
echo '' ; f_Long ; echo -e "NETWORK" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
if [ $rir = "ripe" ] && [[ ${s} =~ $REGEX_IP4 ]] ; then
ac=$(grep -E "^admin-c:" $tempdir/whois | cut -d ':' -f 2- | sed 's/^ *//' | head -1)
resource=$(jq -r '.data.resource' $tempdir/space_usage.json)
assign=$(jq -r '.data.assignments[0] | .address_range' $tempdir/space_usage.json)
allocation=$(jq -r '.data.allocations[0] | .allocation' $tempdir/space_usage.json)
parent=$(jq -r '.data.assignments[0] | .parent_allocation?' $tempdir/space_usage.json | sed '/null/d')
jq -r '.data.allocations[] | {Alloc: .allocation, N: .asn_name, St: .status}' $tempdir/space_usage.json | tr -d '{,"}' | sed 's/^ *//' |
sed '/^$/d' | tr '[:space:]' ' ' | sed 's/Alloc: /\n/g' | sed 's/N:/|/g' | sed 's/St:/|/g' > $tempdir/allocations
suballoc=$(grep -m 1 -w 'SUB-ALLOCATED PA' $tempdir/allocations | cut -d '|' -f 1)
if [ -n "$assign" ] && [ "$resource" = "$assign" ] ; then
n_address="$assign"; n_name=$(jq -r '.data.assignments[0] | .asn_name' $tempdir/space_usage.json)
n_status=$(jq -r '.data.assignments[0] | .status' $tempdir/space_usage.json)
elif [ -n "$suballoc" ] && [ "$resource" = "$suballoc" ] ; then
n_address="$suballoc"; n_name=$(grep -m 1 -w 'SUB-ALLOCATED PA' $tempdir/allocations | cut -d '|' -f 2 | sed 's/^ *//' | tr -d ' ')
n_status=$(grep -m 1 -w 'SUB-ALLOCATED PA' $tempdir/allocations | cut -d '|' -f 3 | sed 's/^ *//') ; fi
if [ "$resource" = "$suballoc" ] || [ "$resource" = "$assign" ] ; then
created=$(grep -E -i -m 1 "^created:|^RegDate:" $tempdir/whois | grep -E -o "[0-9]{4}-[0-9]{2}-[0-9]{2}")
netrange=$(grep -E "^inetnum:|^inet6num:" $tempdir/whois | cut -d ':' -f 2- | sed 's/^ *//' | head -1)
cc=$(grep -E "^country:" $tempdir/whois | awk '{print $NF}' | tr -d ' ' | head -1)
de=$(grep -E "^descr:" $tempdir/whois | cut -d ':' -f 2- | sed 's/^ *//' | head -1)
echo -e "\nNet:         $n_name | $n_address | $n_status"; echo -e "\n             $created, $cc (RIPE)"; fi
if [ -n "$de" ] ; then
echo -e "\nDescr:       $de\n\n" ; else
echo -e "\n"; fi
if [ $rir = "ripe" ] && [[ ${s} =~ $REGEX_IP4 ]] ; then
if [ -n "$parent" ] ; then
whois -h whois.ripe.net -- "--no-personal $parent" > $tempdir/whois; f_netSUM "${parent}"
elif ! [ "$resource" = "$allocation" ] ; then
whois -h whois.ripe.net -- "--no-personal $allocation" > $tempdir/whois ; f_netSUM "${allocation}" ;else
f_netSUM "${resource}"; fi ; fi ; else
echo ''; f_netSUM "${s}" ; fi; echo '' ; f_ORG "$tempdir/whois"
if ! [ $rir = "arin" ] ; then
if ! [ $rir = "ripe" ] || ! [[ ${s} =~ $REGEX_IP4 ]] ; then
ac=$(grep -E "^admin-c:" $tempdir/whois | cut -d ':' -f 2- | sed 's/^ *//' | head -1) ;fi
echo '' ; f_Long; f_ADMIN_C "${ac}"; fi
echo '' ; f_PREFIX "${pfx}"; fi
}
f_hostSHORT(){
local s="$*" ; curl -s -m3 "http://ip-api.com/json/${s}?fields=50390795" > $tempdir/geo.json
ipaddr=$(jq -r '.query' $tempdir/geo.json); org=$(jq -r '.org' $tempdir/geo.json)
geo=$(jq -r '.country' $tempdir/geo.json);regio=$(jq -r '.regionName' $tempdir/geo.json)
isp=$(jq -r '.isp' $tempdir/geo.json)
offset=$(($(jq -r '.offset' $tempdir/geo.json) / 3600)); org=$(jq -r '.org' $tempdir/geo.json)
if [ -n "$org" ] ; then
orgn="$org" ; else
orgn="$isp" ; fi
if [[ ${ipaddr} =~ $REGEX_IP4 ]] ; then
reverse=$(echo $ipaddr | awk -F'.' '{printf $4 "." $3 "." $2 "." $1}')
abx=$(dig +short $reverse.abuse-contacts.abusix.zone txt | tr -d '/"') ; else
if ! [ $option_connect = "0" ] ; then
nibble=$(host $ipaddr | cut -d ' ' -f 1 | rev | cut -d '.' -f 3- | rev)
abx=$(dig +short $nibble.abuse-contacts.abusix.zone txt | tr -d '/"') ; fi ; fi
curl -s "https://stat.ripe.net/data/network-info/data.json?resource=${ipaddr}" > $tempdir/net.json
autn=$(jq -r '.data.asns[0]' $tempdir/net.json); pfx=$(jq -r '.data.prefix' $tempdir/net.json)
curl -s "https://stat.ripe.net/data/as-overview/data.json?resource=AS${autn}" > $tempdir/asov.json
hosting=$(jq -r '.hosting' $tempdir/geo.json | sed '/false/d')
if [ -n "$hosting" ] ; then
is_hosting="| Hosting: $hosting" ; else
is_hosting='' ; fi
if [ $target_type = "dnsrec" ] ; then
curl -m 5 -s "https://stat.ripe.net/data/reverse-dns-ip/data.json?resource=${ipaddr}" > $tempdir/rdns.json
ptr=$(jq -r '.data.result[0]?' $tempdir/rdns.json | sed '/null/d')
if [ -n "$ptr" ] ; then
echo -e "\n$s - rDNS: $ptr"; else 
echo "\n$s" ; fi ; fi 
echo -e "\n$ipaddr | $regio, $geo (UTC $offset) $is_hosting"
if ! [[ ${ipaddr} =~ $REGEX_IP4 ]] ; then
ipv6_info=$(${PATH_nmap} -6 -sn -Pn $s --script address-info.nse 2>/dev/null | grep -E -A 1 "\||\|_|ISATAP" | sed '/--/d' | sed '/address-info:/d' |
tr -d '|_' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' | sed 's/MAC address:/MAC/' | tr '[:space:]' ' '; echo '')
if [ -n "$ipv6_info" ]; then
echo -e "\n$ipv6_info" ; fi; fi 
if [ -n "$abx" ] ; then
echo -e "\n$abx" ; fi
echo -e "\n$orgn | $pfx | AS $autn - $(jq -r '.data.holder' $tempdir/asov.json)\n"
}
f_recordINFO(){
local s="$*"; f_geoWHOIS "${s}" ; cloud_service=''; hosting=$(jq -r '.hosting' $tempdir/geo.json)
if ! [[ ${s} =~ $REGEX_IP4 ]] ; then
housing="Hosting: $hosting"; else
if [ $domain_enum = "true" ] || [ $option_bl="y" ] ; then
curl -s "https://isc.sans.edu/api/ip/${s}?json" > $tempdir/iscip.json; f_threatSUMMARY "${s}" >> $tempdir/isc
ip_num=$(jq -r '.ip.number?' $tempdir/iscip.json)
if [ -n "$ip_num" ] ; then
cloud_service=$(jq -r '.ip.cloud?' $tempdir/iscip.json | sed '/null/d'); fi
if [ -n "$cloud_service" ] ; then
housing="Cloud:  $cloud_service" ; else
housing="Hosting:  $hosting" ; fi ; else
housing="Hosting: $hosting"; fi ; fi
f_Long; echo "$record_type | $record_ip | $housing | $record_nme" ; f_Long; f_ABUSE_C "${s}"; f_hostINFO "${s}"; echo ''
}
f_LOCAL(){
local s="$*" ; f_geoWHOIS "${s}" ; echo ''; f_Long; echo "[+] Public IP: $s"; f_Long ; f_ABUSE_C "${s}" ; f_hostLOCATION "${s}"
}
f_WEB(){
local s="$*" ; f_geoWHOIS "${s}"; geo_cc=$(jq -r '.countryCode' $tempdir/geo.json); cloud_service=''
hosting=$(jq -r '.hosting' $tempdir/geo.json)
if [ $domain_enum = "true" ] && [[ ${s} =~ $REGEX_IP4 ]] ; then
curl -s "https://isc.sans.edu/api/ip/${s}?json" > $tempdir/iscip.json
f_threatSUMMARY "${s}" >> $tempdir/isc
ip_num=$(jq -r '.ip.number?' $tempdir/iscip.json)
if [ -n "$ip_num" ] ; then
cloud_service=$(jq -r '.ip.cloud?' $tempdir/iscip.json | sed '/null/d'); fi
if [ -n "$cloud_service" ] ; then
housing="Cloud:  $cloud_service" ; else
housing="Hosting:  $hosting" ; fi
echo ''; f_Long; echo "[+]  $s  | $geo_cc | AS $as |  $housing"; f_Long; else
echo ''; f_Long; echo "[+]  $s  | $geo_cc | AS $as "; f_Long; fi; f_ABUSE_C "${s}" ; f_hostINFO "${s}"
}
f_HOP(){
local s="$*"; f_geoWHOIS "${s}"; geo_cc=$(jq -r '.countryCode' $tempdir/geo.json); echo ''
if [ -n "$as" ] ; then
export as ; f_Long ; echo "HOP |  $s  |  $geo_cc  ($rir) |  AS $as  |  ROA:  $(jq -r '.data.status' $tempdir/rpki.json)" ; f_Long ; else
echo "HOP |  $s"; f_Long ; fi
f_ABUSE_C "${s}"; f_hostINFO "${s}"
if [ -f $tempdir/whois ] ; then
rm $tempdir/whois ; fi
if [ -f $tempdir/net.json ] ; then
rm $tempdir/net.json ; fi
if [ -f $tempdir/as_sum ] ; then
rm $tempdir/as_sum ; fi
}
f_TYPE_HOSTNAME() {
local s="$*"; f_geoWHOIS "${s}"; geo_cc=$(jq -r '.countryCode' $tempdir/geo.json); whois_reg=$(echo $rir | tr [:lower:] [:upper:]); echo ''
f_Long; echo "[+] $s | $geo_cc | $whois_reg | AS $as "; f_Long; f_ABUSE_C "${s}" ; f_hostINFO "${s}"
if  [ $option_banners = "true" ] ; then
f_BANNERS "${s}" ; echo '' ; fi
if  [ $option_bl = "y" ] ; then
f_Long; echo -e "IP REPUTATION\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' ; f_IP_REPUTATION "${s}" ; echo '' ; fi
}
f_NMAP_HT(){
local s="$*" ; echo '' ; f_Long; echo -e "NMAP\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
curl -s https://api.hackertarget.com/nmap/?q=${s}${api_key_ht} | sed '/PORT/{x;p;x;G}'
echo -e "\nSource: hackertarget.com IP API\n"
}

#********************** HOST & NETWORK SERVICE BANNERS (hackertarget IP Tools API) ***********************
f_BANNERS(){
local s="$*" ; curl -s https://api.hackertarget.com/bannerlookup/?q=${s}${api_key_ht} > $tempdir/banners.json
jq -r '{IP: .ip, SSH: .ssh, FTP: .ftp, Telnet: .telnet, http80_Server: .http80.server, http80_Title: .http80.title, RDP: .rdp, https443_Server: .https443.server, https443_Title: .https443.title, https443_CN: .https443.cn, https443_Org: .https443.o, http8080_Server: .http8080.server, http8080_Title: .http8080.title, https8443_Server: .https8443.server, https8443_Title: .https8443.title, https8443_CN: .https8443.cn}' $tempdir/banners.json | tr -d '{,"}' | sed 's/^ *//' | sed '/^$/d' |
sed 's/Server: null/Server: unknown/g' | sed '/null/d' | sed '/^$/d' | sed 's/http8080_Server:/http9090_Server:/g' |
sed 's/https8443_Server:/https9553_Server:/g' | sed 's/http80_Title:/| Title:/g' | sed 's/https443_Title:/| Title:/g' | sed 's/https443_CN:/| CN:/g' |
sed 's/https443_Org:/| Org:/g' | sed 's/http8080_Title:/| Title:/g' | sed 's/https8443_Title:/|Title:/g' |
sed 's/https8443_CN:/| CN:/g' | tr '[:space:]' ' ' | sed 's/RDP:/\nRDP:/g' | sed 's/Telnet:/\nTelnet:/g' | sed 's/https443/\n\https443/g' |
sed 's/http80/\n\http80/g' | sed 's/http9090/\n\http9090/g' | sed 's/https9553/\n\https9553/g' | sed 's/IP:/\n\IP:/g' | sed 's/FTP:/\n\FTP:/g' |
sed 's/SSH:/\n\SSH:/g' | sed 's/RDP:/\nRDP:/g' | sed 's/Teknet:/\nTelnet:/g' | sed 's/unknown |/un|/g' | sed '/unknown/d' | sed 's/_Server:/ Server:/g' |
sed 's/http80/\nhttp80/g' | sed 's/https443/\nhttps443/g' | sed 's/http9090/\nhttp9090/g' | sed 's/FTP:/\nFTP:/g' | sed 's/SSH:/\nSSH:/g' |
sed 's/IP:/\n\nIP:/g' | sed 's/server: //g' | sed 's/Server: un| //g' | sed 's/http80/80\/HTTP/g' | sed 's/https443/443\/HTTPS/g' |
sed 's/http9090/9090\/HTTP/g' | sed 's/https9553/9553\/HTTP/g'  | sed 's/IP:/*/g' | sed 's/9090\/HTTP/8080\/HTTP/g' |
sed 's/9553\/HTTP/8443\/HTTP/g' > $tempdir/banners.txt
echo '' >> $tempdir/banners.txt
if [ $target_type = "net" ] ; then
cat $tempdir/banners.txt; else
f_Long; echo "BANNERS" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; cat $tempdir/banners.txt | sed '/./,$!d'
if [ $target_type = "default" ] ; then
http80_server=$(jq -r '.http80.server' $tempdir/banners.json | sed '/null/d')
http80_title=$(jq -r '.http80.title' $tempdir/banners.json | sed '/null/d')
https_server=$(jq -r '.https443.server' $tempdir/banners.json | sed '/null/d')
https_cn=$(jq -r '.https443.cn' $tempdir/banners.json | sed '/null/d')
if [ -n "$http80_server" ] || [ -n "http80_title" ] ; then
echo "$http80_server" >> $tempdir/http; echo "$http80_title" >> $tempdir/http ; fi
if [ -n "$https_server" ] || [ -n "$https_cn" ] ; then
echo "$https_server" >> $tempdir/http; echo "$https_cn" >> $tempdir/http ; fi ; fi ; fi
}

#********************** WEBSITE - WEB-TECHNOLOGIES & CONTENT ***********************
f_TITLE(){
local s="$*"
if [ $option_connect = "0" ] ; then
title=$(grep -s -oP '(Title\[).*?(?=\])' $tempdir/ww.txt | tail -1 | sed 's/Title\[//' | tr -d '][' | sed 's/^ *//') ; else
if ! type lynx &> /dev/null; then
title=$(grep -E "<title>|</title>" $s | sed -e :a -e 's/<[^>]*>//g;/</N;//ba' | sed 's/^[ \t]*//;s/[ \t]*$//') ; else
title=$(lynx -crawl -dump $s | grep -s TITLE | sed 's/THE_TITLE://' | sed 's/^[ \t]*//;s/[ \t]*$//') ; fi ; fi
echo -e "\nTitle:         $title"
}
f_linkDUMP(){
local s="$*"
if [ -z "$PATH_lynx" ]; then
$option_source="2"; fi
echo '' > $tempdir/LINKS.${s}.txt; f_Long >> $tempdir/LINKS.${s}.txt
echo -e "[+] $s | LINK DUMP | $(date)" >> $tempdir/LINKS.${s}.txt ; f_Long >> $tempdir/LINKS.${s}.txt
echo '' >> $tempdir/LINKS.${s}.txt
if [ $option_source = "2" ] || [ -z "$PATH_lynx" ]; then
curl -s https://api.hackertarget.com/pagelinks/?q=${s}${api_key_ht} > $tempdir/linkdump.txt
cat $tempdir/linkdump.txt | sort -u >> $tempdir/LINKS.${s}.txt
echo -e "\n\nSource: hackertarget.com IP API\n" >> $tempdir/LINKS.${s}.txt ; else
if ! [ $option_connect = "0" ] ; then
timeout 3 ${PATH_lynx} -accept_all_cookies -dump -listonly -nonumbers ${s} > $tempdir/linkdump_raw
timeout 3 ${PATH_lynx} -accept_all_cookies -dump -listonly -nonumbers ${eff_url} >> $tempdir/linkdump_raw
cat $tempdir/linkdump_raw | sort -f -u | sed '/Sichtbare Links:/d' | sed '/Versteckte Links:/d' |
sed '/[Vv]isible [Ll]inks:/d' | sed '/[Hh]idden [Ll]inks:/d' > $tempdir/linkdump.txt ; fi
if [ $domain_enum = "true" ] && [ -n "$PATH_lynx" ]; then
curl -s https://api.hackertarget.com/pagelinks/?q=${s}${api_key_ht} > $tempdir/linkdump.txt; fi 
cat $tempdir/linkdump.txt | sort -u >> $tempdir/LINKS.${s}.txt ; fi
grep -E "^http:.*|^https:.*|^www.*|" $tempdir/linkdump.txt > $tempdir/linkdump
cat $tempdir/LINKS.${s}.txt >> ${outdir}/LINK_DUMP.${s}.txt
hosts_unique=$(grep -E "^http:.*|^https:.*|^www.*" $tempdir/linkdump | sed 's/http:\/\///' |
sed 's/https:\/\///' | cut -d '/' -f 1 | sort -u)
if [ -n "$hosts_unique" ] ; then
echo '' >> ${outdir}/LINK_DUMP.${s}.txt; f_Short  >> ${outdir}/LINK_DUMP.${s}.txt; echo -e "* Hosts\n" >> ${outdir}/LINK_DUMP.${s}.txt
for h in $hosts_unique ; do
ip_address=$(host -t a $h | grep 'has address' | awk '{print $NF}' | head -6 | tr '[:space:]' ' ')
echo -e "$h \n     $ip_address\n" ; done >> ${outdir}/LINK_DUMP.${s}.txt ; fi
}
f_ROBOTS(){
local s="$*"
status_humans=$(curl -sLk $s/humans.txt -o $tempdir/humans -w %{http_code})
if [ $status_humans = "200" ] ; then 
cat $tempdir/humans > $tempdir/humans.txt 
if [[ $(grep -i -o "DOCTYPE" $tempdir/humans.txt | wc -w ) -gt 0 ]] ; then
rm $tempdir/humans.txt ; rm $tempdir/humans; else
rm $tempdir/humans; cat $tempdir/humans.txt >> $tempdir/cms
f_Long >> ${outdir}/HUMANS.${x}.txt ; cat $tempdir/humans.txt >> ${outdir}/HUMANS.${x}.txt ; fi ; fi
status_robots=$(curl -sLk $s/robots.txt -o $tempdir/robots -w %{http_code})
if [ $status_robots = "200" ] ; then 
cat $tempdir/robots > $tempdir/robots.txt 
if [[ $(grep -i -o "DOCTYPE" $tempdir/robots.txt | wc -w ) -gt 0 ]] ; then
rm $tempdir/robots.txt ; rm $tempdir/robots; else
rm  $tempdir/robots; cat $tempdir/robots.txt >> $tempdir/cms
f_Long >> ${outdir}/ROBOTS.${x}.txt ; cat $tempdir/robots.txt >> ${outdir}/ROBOTS.${x}.txt ; fi ; fi
}

f_PAGE(){
local s="$*" ; echo ''
if [ $option_connect = "0" ] ; then
targetURL=$(cut -s -d ']' -f 1 $tempdir/ww.txt | sed 's/\[/ /' | tail -1) ; else
status=$(grep -E "^Status:" $tempdir/response | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/HTTP /HTTP\//')
targetURL=$(grep -E "^URL:" $tempdir/response | cut -d ':' -f 2- | tr -d ' ') ; f_ROBOTS "${s}" ; fi
targetHOSTNAME=$(echo $eff_url | sed 's/http:\/\///' | sed 's/https:\/\///' | cut -d '/' -f 1)
if echo $s | grep -q -E "\.edu\.|\.co\.|\.org.|\.gov\."; then
page_dom=$(echo $s | sed 's/http:\/\///' | sed 's/https:\/\///' | cut -d '/' -f 1 | rev | cut -d '.' -f 1,2,3 | rev) ; else
page_dom=$(echo $s | sed 's/http:\/\///' | sed 's/https:\/\///' | cut -d '/' -f 1 | rev | cut -d '.' -f 1,2 | rev) ; fi
if echo $targetURL | grep -q -E "\.edu\.|\.co\.|\.org.|\.gov\."; then
targetURL_dom=$(echo $eff_url | sed 's/http:\/\///' | sed 's/https:\/\///' | cut -d '/' -f 1 | rev | cut -d '.' -f 1,2,3 | rev) ; else
targetURL_dom=$(echo $eff_url | sed 's/http:\/\///' | sed 's/https:\/\///' | cut -d '/' -f 1 | rev | cut -d '.' -f 1,2 | rev) ; fi
if [ $option_connect = "0" ] ; then
if [ $domain_enum = "true" ] ; then
f_domainSTATUS "${s}"; f_Long ; echo "[+] $s | DOMAIN WEBSITE" ; f_Long ; echo '' ; else
f_Long; echo "WHATWEB" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
echo -e "\nURL:           $targetURL" ; fi
target_email=$(grep -s -oP '(Email\[).*?(?=])' $tempdir/ww.txt | sed 's/Email\[/\nEmail:         /' | tr -d ']' | sed 's/,/, /g')
httpserver=$(grep -s -oP '(HTTPServer\[).*?(?=\])' $tempdir/ww.txt | sed 's/HTTPServer\[//' | sed 's/^ *//' | tail -1)
cms=$(grep -s -E -i -o -m 1 "wordpress|typo3|joomla|drupal|liferay|librecms|wix" $tempdir/ww.txt | sort -u -V | tail -1)
google_a=$(grep -s -oP -m 1 '(Google-Analytics\[).*?(?=\,)' $tempdir/ww.txt)
if [ -n "$cms" ] ; then
cms_output="$cms" ; else
cms_output="none/unkown" ; fi ; f_TITLE
if [ -n "$target_email" ] ; then
echo -e "$target_email\n" ; fi
echo -e "\nServer:        $httpserver  |  CMS: $cms_output\n"
if [ -n "$google_a" ] ; then
echo -e "Google:        Analytics: $google_a\n"; fi
f_Long; f_wwMARKUP ; echo ''
if [ -n "$api_key_ht" ]; then
f_Long; echo -e "HTTP HEADERS\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
curl -s -m 5 "https://api.hackertarget.com/httpheaders/?q=${s}${api_key_ht}" > $tempdir/headers
echo '' >> $tempdir/headers; cat $tempdir/headers
f_Long; echo -e "LINK DUMP\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
curl -s -m 5 https://api.hackertarget.com/pagelinks/?q=${s}${api_key_ht} > $tempdir/linkdump
echo '' >> $tempdir/linkdump; cat $tempdir/linkdump ; fi
if [ $domain_enum = "true" ] ; then
f_certINFO "${s}"
if ! [ "$page_dom" = "$target_url_dom" ] ; then
f_certINFO "$target_url_dom" ; fi
f_DNS_REC "${s}"
if [ $option_zone = "1" ] || [ $option_zone = "3" ] ; then
echo ''; f_Long; echo "[+] DNS RECORDS | IP REPUTATION CHECK"; f_Long
echo -e "\nChecking ...\n" | tee -a ${out}
echo -e "$blocklists_domain" | sed '$!s/$/,/' | sed '1,1d' | tr '[:space:]' ' ' | fmt -s -w 90
echo -e "Project Honeypot, Stop Forum SPAM, Spamhaus ZEN & Grey Noise Community API\n"
for i in $(cat $tempdir/ips.list | sort -uV); do
f_IP_REPUTATION "${i}" ; done ; fi
if [ $option_zone = "2" ] || [ $option_zone = "3" ] ; then
f_AXFR "${page_dom}" ; fi
f_subs_HEADER "${s}" ; cat ${outdir}/Subdomains_HT.${s}.txt
if [ $option_whois = "y" ] ; then
cat $tempdir/domain_nets ; fi ; fi; else
endpoint=$(grep 'Connected to' $tempdir/curl_trimmed | tail -1 | awk '{print $3,$4}')
google_a=$(grep -a -m 1 -E -o "UA-.*.-[0-9]" $tempdir/page_src)
if [ -f $tempdir/ww.txt ] ; then
cms=$(grep -a -E -i -o -m 1 "wordpress|typo3|joomla|drupal|liferay|librecms|wix" $tempdir/ww.txt | sort -uV | tail -1)
httpserver=$(grep -s -oP '(HTTPServer\[).*?(?=\])' $tempdir/ww.txt | sed 's/HTTPServer\[//' | sed 's/^ *//' | tail -1); else
httpserver=$(grep -i -E "^Server:" $tempdir/headers  | cut -d ':' -f 2 | sed 's/^[ \t]*//;s/[ \t]*$//' | tail -1)
cms=$(grep -s -E -i -o "wordpress|wp-content|wp-includes|wp-admin|typo3|typo3search|typo3conf|typo3.conf|joomla|drupal|liferay|librecms|wix" $tempdir/cms |
sed 's/typo3conf/typo3/g' | sed 's/typo3.conf/typo3/g' | sed 's/typo3search/typo3/g' | sed 's/TYPO3SEARCH/TYPO3/g' |
sed 's/wp-content/wordpress/g' | sed 's/wp-admin/wordpress/g' | sed 's/wp-includes/wordpress/g' | sed 's/^[ \t]*//;s/[ \t]*$//' | tr [:lower:] [:upper:] |
sort -uV | tail -1) ; rm $tempdir/cms ; fi
if [ $domain_enum = "true" ] ; then
f_Long ; echo "[+]  DOMAIN WEBSITE" ; f_Long
echo -e "\nHost           $endpoint" ; f_detectCDN "$tempdir/headers" ; else
verify=$(grep -s -m 1 'SSL certificate verify' $tempdir/curl_trimmed | rev | cut -d ' ' -f 1 | rev | tr -d '.')
f_Long ; echo "$s | CERT: $verify | STATUS: $status" ; f_Long
echo -e "\nURL:           $targetURL" ; fi
f_TITLE "$tempdir/page.html"
if [ -f $tempdir/ww.txt ] ; then
if [ -n "$cms" ] ; then
cms_output="$cms" ; else
cms_output="none/unkown" ; fi
echo -e "\nServer:        $httpserver | CMS: $cms_output" ; else
echo -e "\nServer:        $httpserver"
if [ -n "$cms" ] ; then
echo -e "\nCMS:           $cms" ; fi ; fi
if [ -n "$google_a" ] ; then
echo -e "\nGoogle         Goolge Analytics: $google_a" ; fi; echo ''
if [ $page_details = "true" ] ; then
timeout 5 ${PATH_lynx} -accept_all_cookies -crawl -dump -nonumbers $s > $tempdir/pages_text
doctype=$(grep -E -i "<\!doctype" $tempdir/page_src | grep -i -o -E "XHTML.[1-2]|HTML.[1-4]|<\!doctype html>" | tr [:lower:] [:upper:] |
sed 's/<!DOCTYPE HTML>/HTML5/')
grep -E -i -o "gtm\.js|googletagmanager" $tempdir/src_scripts | head -1 | sed 's/gtm.js/GoogleTagManager/' |
sed 's/googletagmanager/GoogleTagManager/' >> $tempdir/google
grep -o -m 1 'cookiebot' $tempdir/src_scripts | sed 's/cookiebot/Cookiebot/' >> $tempdir/google
grep -o -m 1 'google.com/recaptcha' $tempdir/src_scripts | sed 's/google.com\/recaptcha/Google_Recaptcha/' >> $tempdir/google
grep -o 'maps.googleapis.com' $tempdir/src_scripts | head -1 | sed 's/maps.googleapis.com/GoogleMapsAPI/' >> $tempdir/google
grep -E "src=|href=" $tempdir/page_src | grep 'fonts.googleapis' | grep -soP '(family=).*?(?=\,)' | sed 's/family=/GoogleWebFonts=/'  >> $tempdir/google
grep -E "src=|href=" $tempdir/page_src | grep 'fonts.googleapis' | grep -soP '(family=).*?(?=\")' | sed 's/family=/GoogleWebFonts=/' >> $tempdir/google
grep -E "src=|href=" $tempdir/page_src | grep -E -o "google_analytics.js" >> $tempdir/google
google_stuff=$(cat $tempdir/google | sed 's/^ *//' | sed '/^$/d' | sort -ufV | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | sed 's/GoogleWebFonts=/GoogleWebFonts: /')
grep -o -m 1 'umami.js' $tempdir/src_scripts >> $tempdir/webtech; grep -o -m 1 'html5shiv.js' $tempdir/src_scripts >> $tempdir/webtech
grep -o 'xmlrpc.php' $tempdir/page_src >> $tempdir/webtech
grep 'rel="stylesheet"' $tempdir/page_src | grep -o font-awesome | sed 's/font-awesome/FontAwesome/g' > $tempdir/fonta
grep -E -o "<i class=\"fas|<i class=\"fab|<i class=\"fa" $tempdir/page_src | sed 's/<i class=\"fas/FontAwesome/g' |
sed 's/<i class=\"fab/FontAwesome/g' | sed 's/<i class=\"fa/FontAwesome/g' | tail -1  >> $tempdir/fonta
grep -E "src=|href=" $tempdir/page_src | grep -soP '(type=").*?(?=")' | grep -E -o "text/\b[A-Za-z0-9.+]{1,30}\b|application/\b[A-Za-z0-9.+]{1,30}\b" |
sed 's/^ *//' | sed '/^$/d' >> $tempdir/mime_types
if [[ $(cat $tempdir/fonta | wc -l) -gt 2 ]] ; then
cat $tempdir/fonta | sort -u | tail -1 >> $tempdir/webtech; fi
if [[ $(grep 'IFRAME' $tempdir/pages_text | wc -w) -gt 1 ]] ; then
grep 'IFRAME' $tempdir/pages_text >> $tempdir/webtech ; else
grep -o -m 1 '<iframe' $tempdir/page_src | sed 's/<iframe/Frame/' >> $tempdir/webtech ; fi
if ! [ -f $tempdir/ww.txt ] ; then
x_powered=$(grep -E -i -a -m 1 "^X-Powered-By:" $tempdir/headers | cut -d ':' -f 2- | sed 's/^ *//'); fi
x_gen=$(grep -E -i -a -m 1 "^X-Generator:" $tempdir/headers | cut -d ':' -f 2- | sed 's/^ *//')
rss_feed=$(grep -i 'application/rss+xml' $tempdir/page_src | grep -E -o "href=*.*>" | head -1 | cut -d '"' -f 2)
f_Long ; echo -e "MARKUP" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
echo "Doctype:       $doctype"
grep -sioP '(meta charset=").*?(?=")' $tempdir/page_src | sed 's/meta charset=\"/Charset:       /'
head -15 $tempdir/page_src | grep -sioP '(lang=").*?(?=")' $tempdir/page_src | sed 's/lang=\"/Language:      /'
if [ -f $tempdir/ww.txt ] ; then
f_wwMARKUP ; else
powered_by=$(grep -A 5 '<!--' $tempdir/page_src | grep -i 'powered by' | sed 's/By/by/' | awk -F'by' '{print $2}' | awk '{print $1}')
if [ -n "$powered_by" ] ; then
echo "Powered by:    $powered_by"; fi
grep -soP '(name="generator" content=").*?(?=")' $tempdir/page_src | sed 's/name=\"generator\"/Generator:    /' | sed 's/content="//' | awk -F'\"' '{print $1}'
grep -soP '(name="author" content=").*?(?=")' $tempdir/page_src | sed 's/name=\"author\"/Author:       /' | sed 's/content="//' | awk -F'\"' '{print $1}'
if [ -n "$x_powered" ] ; then
echo "X-Powered By: $x_powered"; fi; fi
if [ -n "$x_gen" ] ; then
echo "X-Generator:  $x_gen"; fi
grep -sioP '(name="copyright" content=").*?(?=")' $tempdir/page_src | sed 's/name=\"copyright\"/Copyright:     /' | sed 's/content="//' | awk -F'\"' '{print $1}'
grep -sioP '(name="last-modified" content=").*?(?=")' $tempdir/page_src | sed 's/name=\"last-modified\"/Last modified: /' | sed 's/content="//' |
awk -F'\"' '{print $1}'
metarob=$(grep -sP '(name="robots" content=").*?(?=")' $tempdir/page_src | awk -F'content=\"' '{print $2}' | awk -F'\"' '{print $1}' | tr '[:space:]' ' ' |
sed 's/^ *//'; echo '')
if [ -n "$metarob" ] ; then
echo -e "MetaRobots:    $metarob" ; fi
if [ -n "$google_stuff" ] ; then
if [ -n "$google_a" ] ; then
echo ''; fi
echo "Google:        $google_stuff"
if [ -n "$google_a" ] ; then
echo -e "\n              Goolge Analytics ID: $google_a\n" ; fi; fi
if [ -n "$rss_feed" ] ; then
echo "RSSFeed:        $rss_feed" | sed 's/href=//' | tr -d '>'; fi
webtech_other=$(cat $tempdir/webtech | sed 's/^ *//' | sed '/^$/d' | sort -ufV | tr '[:space:]' ' '; echo '')
if [ -n "$webtech_other" ] ; then
echo -e "Other:         $webtech_other\n"; fi
echo -e "\n\n* MIME Types (application, text)\n"; cat $tempdir/mime_types | sort -u ; echo ''
script_src=$(grep '<script' $tempdir/page_src | grep -soP '(src=\").*?(?=\")' | awk -F'src=\"' '{print $2}' | awk -F'\"' '{print $1}')
if [ -n "$script_src" ] ; then
f_Long ; echo -e "SCRIPTS\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
echo -e "\n$script_src\n\n" | fmt -w 120; fi
theme_info=$(sed -n '/<head>/,/<\/head>/p' $tempdir/page_src | grep -E "Theme:|Version:|WP:")
if [ -n "$theme_info" ] ; then
f_Long ; echo -e "WP THEME INFO\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
echo -e "$theme_info\n" | fmt -w 120; fi
page_descr=$(grep -siP '(name="description" content=").*?(?=")' $tempdir/page_src | awk -F'content=\"' '{print $2}' | awk -F'\"' '{print $1}')
page_keyw=$(grep -siP '(name="keywords" content=").*?(?=")' $tempdir/page_src | awk -F'content=\"' '{print $2}' | awk -F'\"' '{print $1}' | sed 's/,/ /g')
if [ -n "$page_descr" ] ; then
f_Long; echo -e "DESCRIPTION" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; echo -e "$page_descr\n" | fmt -w 60 -s ; fi
og_locale=$(cat $tempdir/page_src | grep -soP '(property=\"og:locale).*?(?=/>)' | grep -soP '(content=\").*?(?=\")' |
sed 's/content=\"/Locale: /')
og_type=$(cat $tempdir/page_src | grep -soP '(property=\"og:type).*?(?=/>)' | grep -soP '(content=\").*?(?=\")' | sed 's/content=\"/Type: /')
og_url=$(cat $tempdir/page_src | grep -soP '(property=\"og:url).*?(?=/>)' | grep -soP '(content=\").*?(?=\")' | sed 's/content=\"/URL:/')
if [ -n "$og_type" ] ; then
echo "$og_type  $og_locale" > $tempdir/ograph; fi
cat $tempdir/page_src | grep -soP '(property=\"og:url).*?(?=/>)' | grep -soP '(content=\").*?(?=\")' | sed 's/content=\"/\nURL:  /' >> $tempdir/ograph
cat $tempdir/page_src | grep -soP '(property=\"og:title).*?(?=/>)' | grep -soP '(content=\").*?(?=\")' |
sed 's/content=\"/\nTitle:\n\n/' | sed 's/^ *//' >> $tempdir/ograph
cat $tempdir/page_src | grep -soP '(property=\"og:description).*?(?=/>)' | grep -soP '(content=\").*?(?=\")' |
sed 's/content=\"/\nDescription:\n\n/' | sed 's/^ *//' >> $tempdir/ograph
if [[ $(cat $tempdir/ograph | wc -w) -gt 1 ]] ; then
f_Long; echo -e "OPEN GRAPH PROTOCOL" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
cat $tempdir/ograph | fmt -s -w 60; fi
if [ -n "$page_keyw" ] ; then
if [ -n "$page_descr" ] || [[ $(cat $tempdir/ograph | wc -w) -gt 1 ]] ; then
echo '' ; else
f_Long; fi
echo -e "KEYWORDS" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; echo "$page_keyw" | fmt -w 60 -s ; fi
echo ''; cat $tempdir/page.html > $tempdir/pages; f_linkDUMP "${s}"
curl -sLk ${curl_ua} ${targetURL} >> $tempdir/pages
curl -sLk ${curl_ua} ${targetURL}/impressum >> $tempdir/pages
curl -sLk ${curl_ua} ${targetURL}/contact-us >> $tempdir/pages
curl -sLk ${curl_ua} ${targetURL}/karriere >> $tempdir/pages
curl -sLk ${curl_ua} ${targetURL}/jobs >> $tempdir/pages
for site in $subpages1 ; do
curl -sLk ${curl_ua} ${s}/$site >> $tempdir/pages ; done
for site2 in $subpages2 ; do
curl -sLk ${curl_ua} ${site2}.${targetURL_dom} >> $tempdir/pages; done
grep -s -i -F -econtact -ediscord -ekontakt -efacebook -einstagram -elinkedin -epinterest -etwitter -exing -eyoutube $tempdir/linkdump.txt |
sed '/sport/d' | sed '/program/d' > $tempdir/social
grep -E -i "Phone|Ph:|Telefon:|Tele:|Tel:|Telefone:|Fon:" $tempdir/pages |
grep -E -o "\+[0-9]{2,6}[ -][0-9]{2,6}[ -][0-9]{2,6}[ -][0-9]{2,6}|\(([0-9]\{3\})\|[0-9]\{3\}\)[ -]\?[0-9]\{3\}[ -]\?[0-9]\{4\}" |
tr [:upper:] [:lower:] >> $tempdir/pagecontacts
grep -s -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/linkdump.txt | tr [:upper:] [:lower:] >> $tempdir/pagecontacts
grep -s -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/pages | tr [:upper:] [:lower:] >> $tempdir/pagecontacts
cat $tempdir/pages_text | sed 's/-at-/@/g' |  sed 's/(at)/@/g' | sed 's/@ /@/g' | sed 's/ @/@/g' | tr [:upper:] [:lower:] >> $tempdir/pages.txt
grep -E -i "Phone|Ph:|Telefon:|Tele:|Tel:|Telefone:|Fon:" $tempdir/pages.txt |
grep -E -o "\+[0-9]{2,6}[ -]*[0-9]{2,6}[ -][0-9]{2,6}[ -][0-9]{2,6}|\(([0-9]\{3\})\|[0-9]\{3\}\)[ -]\?[0-9]\{3\}[ -]\?[0-9]\{4\}" >> $tempdir/pagecontacts
grep -s -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/pages.txt | tr [:upper:] [:lower:] >> $tempdir/pagecontacts
if [ -f $tempdir/ww.txt ] ; then
grep -s -oP '(Email\[).*?(?=])' $tempdir/ww.txt | tr -d '][' |  sed 's/Email//' | sed 's/,/\n/' | sed 's/^ *//' >> $tempdir/pagecontacts; fi
f_Long; echo -e "SOCIAL MEDIA & CONTACTS" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' ; echo '' ; cat $tempdir/social | sort -f -u ; echo ''
grep -s -E -i "^tel:|^phone:|^call:|^telefon:" $tempdir/linkdump.txt | cut -d ':' -f 2- | tr -d ' ' | sort -u -V |
grep -E -v "*\.jpg|*\.png|*\.gif|*\.tiff|\*.ico"
cat $tempdir/pagecontacts | sort -u | grep -E -v "*\.jpg|*\.png|*\.gif|*\.tiff|\*.ico"
pixels=$(sed 's/<noscript/\n\n<noscript/g' $tempdir/noquotes | sed 's/<\/noscript>/<\/noscript>\n\n\n/g' | sed 's/<img/\n<img/g' |
grep -E -A 3 "<noscript|<noscript=" | grep -E "height=[0-2]|width=[0-2]")
if [ $domain_enum = "true" ] ; then
if [ -n "$google_a" ] ; then
echo ''; f_Long; search_item=$(echo $google_a | cut -d '-' -f -2); echo -e "Google Analytics ID Reverse Search [$search_item]\n"
rev_ga=$(curl -s https://api.hackertarget.com/analyticslookup/?q=${search_item})
if [ -n "$rev_ga" ] ; then
for ga in $rev_ga ; do
echo -e "$ga   -  $(dig +short $ga)\n" ; done ; fi ; fi ; fi
if [ -n "$pixels" ] ; then
if [ $(echo "$pixel" | wc -w ) -lt "60" ] ; then
f_Long ; echo -e "WEB BEACONS\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' ; echo "$pixels" | sed 's/<noscript/\n<noscript/g' |
sed 's/<\/noscript/\n<\/noscript/g' | sed 's/src=/\nscr=/g'  | sed 's/^[ \t]*//;s/[ \t]*$//' ; fi ; fi ; fi
if [ -f $tempdir/humans.txt ] ; then
if [[ $(cat $tempdir/humans.txt | wc -l) -lt 15 ]] ; then
f_Long ; echo -e "HUMANS.TXT\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
cat $tempdir/humans.txt; fi ; fi
if [ -f $tempdir/robots.txt ] ; then
if [[ $(cat $tempdir/robots.txt | wc -l) -lt 20 ]] ; then
f_Long ; echo -e "HUMANS.TXT\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
cat $tempdir/robots.txt; fi ; fi
if [ $domain_enum = "false" ] ; then
f_DNSWhois_STATUS "${s}" ; fi ; fi ; echo ''
}
f_wwMARKUP(){
if [ -f $tempdir/ww.txt ] ; then
if [ $option_connect = "0" ] ; then
doctype=$(grep -s -o -w 'HTML5' $tempdir/ww.txt | tail -1)
if [ -n "$doctype" ] ; then
doctype="$doctype" ; else
doctype="HTML4.x/XHTML1.x or similar" ; fi
echo -e "Doctype:       $doctype" ; fi
grep -s -oP -m 1 '(Script\[).*?(?=\])' $tempdir/ww.txt | sed 's/\[/:        /' | sed 's/,/, /g'
jqu=$(grep -s -oP '(JQuery\[).*?(?=\,)' $tempdir/ww.txt )
if [ -n "$jqu" ] ; then
echo -e "jQuery:        $jqu" ; fi ; echo '' ; fi
grep -s -oP -m 1 '(Content-Language\[).*?(?=\])' $tempdir/ww.txt | sed 's/Content-Language\[/Language:      /' | tr -d ']'
grep -oP '(Meta-Author\[).*?(?=,)' $tempdir/ww.txt | sed 's/Meta-Author\[/Author:        /' | tr -d '][' | sed 's/^ *//'
grep -s -oP '(PasswordField\[).*?(?=\])' $tempdir/ww.txt | sed 's/PasswordField\[/PasswdField:   /' | tr -d ']'
grep -s -oP '(WWW-Authenticate\[).*?(?=\])' $tempdir/ww.txt | sort -u | sed 's/WWW-Authenticate\[/WWW-Auth.:     /' | tr -d ']['
grep -s -oP '(MetaGenerator\[).*?(?=,)' $tempdir/ww.txt | sort -u -V | sed 's/\[/: /' | tr -d '][' | sed 's/^ *//'
grep -s -oP '(PoweredBy\[).*?(?=\])' $tempdir/ww.txt | sed 's/\[/:     /'
grep -s -oP '(X-Powered-By\[).*?(?=\])' $tempdir/ww.txt | tail -1 | sed 's/\[/:  /'
grep -s -o -w 'Frame' $tempdir/ww.txt | head -1 >> $tempdir/webtech
grep -s -oP -m 1 '(Open-Graph-Protocol\[).*?(?=\])' $tempdir/ww.txt | sed 's/\[/:/' >> $tempdir/webtech
grep -s -oP -m 1 '(OpenSearch\[).*?(?=\])' $tempdir/ww.txt | sed 's/OpenSearch\[/OpenSearch: /' >> $tempdir/webtech
grep -s -oP '(Modernizr\[).*?(?=\])' $tempdir/ww.txt | sort -u | sed 's/Modernizr\[/Modernizr: /' | tr -d '][' >> $tempdir/webtech
grep -o -m 1 'Lightbox' $tempdir/ww.txt >> $tempdir/webtech
if [ $option_connect = "0" ] ; then
grep -s -oP '(X-UA-Compatible\[).*?(?=\])' $tempdir/ww | sed 's/\[/: /' >> $tempdir/webtech
webtech_other=$(cat $tempdir/webtech | sort -ufV | tr '[:space:]' ' '; echo '')
if [ -n "$webtech_other" ] ; then
echo -e "Other:         $webtech_other" ; rm $tempdir/webtech; fi
grep -s -oP '(Via-Proxy\[).*?(?=\])' $tempdir/ww.txt | sed 's/\[/:     /'
uncommon_headers=$(grep -s -oP '(UncommonHeaders\[).*?(?=\])' $tempdir/ww.txt | tr -d '[' | sed 's/,/\n/g' | sed 's/^ *//')
grep -s -oP '(Strict-Transport-Security\[).*?(?=\])' $tempdir/ww.txt | tail -1 | sed 's/\[/: /' | tr -d '][' > $tempdir/sec_headers_ww
grep -s -oP '(X-Frame-Options\[).*?(?=\])' $tempdir/ww.txt | tail -1 | sed 's/\[/:  /' | tr -d ']['  >> $tempdir/sec_headers_ww
grep -s -oP '(X-XSS-Protection\[).*?(?=\])' $tempdir/ww.txt | tail -1 | sed 's/\[/:  /' | tr -d ']['  >> $tempdir/sec_headers_ww
grep -i -o 'content-security-policy' $tempdir/ww.txt | tail -1  >> $tempdir/sec_headers_ww
grep -i -o 'x-content-type-options' $tempdir/ww.txt | tail -1  >> $tempdir/sec_headers_ww
grep -s -oP '(Cookies\[).*?(?=\])' $tempdir/ww.txt | sed 's/\[/:  /' | tr -d ']['  >> $tempdir/sec_headers_ww
grep -s -oP '(HttpOnly\[).*?(?=\])' $tempdir/ww.txt | sed 's/\[/:  /' | tr -d ']['  >> $tempdir/sec_headers_ww
if [ -f $tempdir/sec_headers_ww ] || [ -n "$uncommon_headers" ] ; then
f_Long ; echo -e "UNCOMMON & SECURITY HEADERS\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
echo "$uncommon_headers"; cat $tempdir/sec_headers_ww; rm  $tempdir/sec_headers_ww; fi ; fi
}
f_htmlCOMMENTS(){
local s="$*"
comments=$(${PATH_nmap} -Pn -sT -p 80,443 --script http-comments-displayer ${s} 2>/dev/null | grep -E "80/tcp|443/tcp|\||\|_" | tr -d '|_' |
sed 's/^ *//' | sed 's/Line number:/ | Line:/g' | tr '[:space:]' ' ' | sed 's/Comment:/\n/g' | sed 's/443\/tcp/\n443\/tcp/' |
sed 's/Path:/\n\nPath:/g' | sed '/\/tcp/{x;p;x;G;}' | sed 's/http-comments-displayer:/\n\n/' |
sed 's/^ *//' | sed 's/<\!--/    <\!--/g' | sed 's/\/\*/    \/\*/g')
if [ -n "$comments" ] ; then
echo '' ; f_Long ; echo "[+] $s | HTML Comments" ; f_Long ; echo "$comments" | fmt -s -w 100 ; echo '' ; fi
}

#********************** SSL/TLS ***********************
f_SSLSCAN(){
if [ -z "$PATH_sslscan" ] ; then
echo -e "\nPlease install SSLscan or set path to executable within the drwho.sh file" ; else
local s="$*"
if ! [ $option_sslscan = "0" ] ; then
echo '' ; f_Long
if [ $option_sslscan = "1" ] ; then
echo "SSL CIPHERS & SECURITY - SUMMARY" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
${PATH_sslscan} --no-colour --no-cipher-details --no-groups --no-fallback --show-times $s | sed 's/^ *//' > $tempdir/sslscn
sed -n '/SSL\/TLS Protocols:/,/SSL Certificate/p' $tempdir/sslscn |
grep -E -v "^SSL Certificate:" | sed '/Protocols:/{x;p;x;G}' | sed '/Supported Server/{x;p;x;G;}' | sed '/TLS renegotiation:/{x;p;x;}'; fi
if [ $option_sslscan = "2" ] ; then
echo -e "SERVER CIPHERS - TIMES\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
o="--no-colour --tlsall --no-fallback --no-compression --no-groups --no-heartbleed --no-renegotiation --no-cipher-details --no-check-certificate --show-times"
${PATH_sslscan} ${o} ${s} | sed 's/^ *//' > $tempdir/sslscn
sed -n '/Supported Server/,/SSL Certificate:/p' $tempdir/sslscn | sed '/Supported Server/d' | sed '/SSL Certificate:/d' | sed '/^$/d' ; fi
if [ $option_sslscan = "3" ] ; then
if [ $option_starttls = "2" ] ; then
${PATH_sslscan} --no-colour --starttls-imap --no-cipher-details --no-groups --no-fallback --show-times --ocsp $s:$mx_port |
sed 's/^ *//' > $tempdir/sslscn ; else
${PATH_sslscan} --no-colour --starttls-smtp --no-cipher-details --no-groups --no-fallback --show-times --ocsp $s:$mx_port |
sed 's/^ *//' > $tempdir/sslscn ; fi
sed -n '/Connected to/,/Stapling Request/p' $tempdir/sslscn | sed '/Protocols:/{x;p;x;G}' | sed '/Stapling Request/d' |
sed '/TLS renegotiation:/{x;p;x;}'
sed -n '/Stapling Request/,/Supported Server/p' $tempdir/sslscn | grep -E "^OCSP|Cert Status|Update:|Serial Number:|Responder Id:" |
sed '/Cert Status:/{x;p;x;G}' | sed '/Request/{x;p;x;G}'
sed -n '/Supported Server/,/SSL Certificate:/p' $tempdir/sslscn | sed '/Supported Server/{x;p;x;G}' | sed '/SSL Certificate:/d'
sed -n '/Subject:/,/Issuer:/p' $tempdir/sslscn | sed '/Issuer:/d' | sed 's/Subject:/\n\nSubject:\n\n/' |
sed 's/Altnames:/\n\nAltnames:\n\n/' | sed 's/DNS://g' | sed 's/^ *//' | fmt -s -w 80 ; fi ; fi; fi
}
f_testSSL(){
local s="$*" ; target=$(echo $s | sed 's/www.//')
if ! [ $option_testSSL = "0" ] ; then
declare -a testssl_array=()
if [ $option_testSSL = "1" ] ; then
testssl_array+=(--sneaky --phone-out --quiet --warnings off --color 0 -S)
if [ -z "$PATH_sslscan" ]; then
testssl_array+=(-p -E); fi
${PATH_testssl} ${testssl_array[@]} $target | sed 's/^[ \t]*//;s/[ \t]*$//' > $tempdir/testtls
grep -E "^Start|Common Name|DB|OCSP URI|Transparency|Certificates provided|^Chain of|^Trust" $tempdir/testtls |
sed '/Start/i \\n_______________________________________________________________________________\n' |
sed '/Common Name (CN)/{x;p;x;G}' | sed 's/Common Name (CN)             /CN: /g' | sed 's/(CN in response/\n(CN in response/g' | sed 's/^ *//' |
sed 's/^.*\(-->>.*\).*$/\1/g' | sed 's/-->>//g' | sed 's/<<--//g' | sed 's/^ *//' | sed '/Fingerprints/d' | sed '/Trust/{x;p;x;}' | sed '/Serial/d' |
sed '/Chain/G' | sed '/SHA256/d' | sed '/ordered by encryption strength/G' |
sed '/Testing ciphers/i \\n______________________________________________________________________________\n'
elif [ $option_testSSL = "2" ] ; then
testssl_array+=(--sneaky --phone-out --quiet --warnings off --color 0 -S -p)
${PATH_testssl} ${testssl_array[@]} $target | sed 's/^[ \t]*//;s/[ \t]*$//' > $tempdir/testtls
grep -E "^Start|Common Name|OK|DB|OCSP URI|Transparency|Certificates provided|^Chain of|^Trust" $tempdir/testtls |
sed '/Start/i \\n___________________________________________________________\n' |
sed '/Common Name (CN)/i \\n___________________________________________________________\n' |
sed '/Common Name (CN)/G' | sed 's/Common Name (CN)             /CN: /g' | sed 's/(CN in response/\n(CN in response/g' | sed 's/^ *//' |
sed '/(CN in/a \\n___________________________________________________________\n' |
sed 's/^.*\(-->>.*\).*$/\1/g' | sed 's/-->>//g' | sed 's/<<--//g' | sed 's/^ *//' | sed 's/SSLv2/\n\nSSLv2/g' |
sed '/SSLv3/G' | sed '/Fingerprints/d' | sed '/Trust/{x;p;x;}' | sed '/Serial/d' | sed '/Chain/G' | sed '/SHA256/d'
elif [ $option_testSSL = "3" ] ; then
testssl_array+=(--ids-friendly --warnings off --phone-out --quiet --color 0 -B -S -p -s -f -H -C -R -E)
elif [ $option_testSSL = "4" ] ; then
testssl_array+=(--ids-friendly --warnings off --phone-out --quiet --color 0 -B -S -p -s -f -H -c -C -R)
if [ -z "$PATH_sslscan" ]; then
testssl_array+=(-E); fi ; fi
if [ $option_testSSL = "3" ] || [ $option_testSSL = "4" ] ; then
${PATH_testssl} ${testssl_array[@]} $target | sed 's/^[ \t]*//;s/[ \t]*$//' > $tempdir/testtls
cat $tempdir/testtls |
grep -E "Start|offered|^Trust|^Chain of|^Common Name|DB|Resumption|^Elliptic curves offered:|^DH group offered:|clock skew|Compression|^Client Authentication|URI|transparency|provided|hostname|Issuer|vulnerable|supported|compression|Intermediate|<--|^SSLv.*|TLSv.*|^TLS 1|^TLS 1\.*|^xc.*|KeyExch\.|------|^Testing ciphers per protocol|Running client simulations" |
sed '/Start/i \\n_______________________________________________________________________________\n' | sed 's/SSLv2/\n\nSSLv2/g' | sed '/SSLv3/G' |
sed 's/^.*\(-->>.*\).*$/\1/g' | sed 's/-->>//g' | sed 's/<<--//g' | sed 's/^ *//' | sed '/Fingerprints/d' | sed '/TLS extensions/d' | sed '/Serial/d' |
sed '/Revocation/d' | sed '/NULL ciphers/i \\n______________________________________________________________\n\n' | sed '/NPN\/SPDY/{x;p;x;}' |
sed '/FS is offered/i \\n______________________________________________________________\n' | sed 's/FS is offered (OK)/FS is offered (OK):\n\n/g' |
sed '/Elliptic curves/i \\n______________________________________________________________\n' | sed '/Triple DES/{x;p;x;}' | sed '/LOW:/G' |
sed '/Resumption/i \\n______________________________________________________________\n\n' | sed '/Obsoleted CBC ciphers/G' |
sed '/Common Name/i \\n______________________________________________________________\n' | sed '/Strong encryption/{x;p;x;}' |
sed 's/Common Name (CN)             /CN: /g' | sed 's/(CN in response/\n(CN in response/g' | sed 's/^ *//' |
sed '/Trust/i \______________________________________________________________\n\n' | sed '/Chain/G' | sed '/SHA256/d' |
sed '/Issuer/i \\n______________________________________________________________\n' | sed 's/Issuer                       /Issuer: /g' |
sed '/Intermediate cert/i \______________________________________________________________\n'
sed '/Intermediate/{x;p;x}' | sed 's/Intermediate cert validity/Intermediate cert validity\n\n/g' | sed 's/^ *//' |
sed '/ordered by encryption strength/G' | sed 's/\nElliptic curves offered:/Elliptic curves offered:\n\n/g' |
sed '/Heartbleed/i \\n______________________________________________________________\n' | sed 's/DH group offered:/\nDH group offered:\n\n/g' |
sed '/Testing ciphers/i \\n______________________________________________________________________________\n\n' |
sed '/Running client/i \\n______________________________________________________________________________\n\n' |
tr -d '#' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/application layer protocol negotiation/d' | sed '/^Done/d' | fmt -s -w 100 ; fi ; fi
}
f_certINFO() {
local s="$*"
if [ $option_connect = "0" ] ; then
curl -s "https://api.certspotter.com/v1/issuances?domain=${s}&expand=dns_names&expand=issuer&expand=cert" > $tempdir/hostcert.json
dnsnames=$(jq -r '.[].dns_names | .[]' $tempdir/hostcert.json)
if [ -n "$dnsnames" ] ; then
echo '' ; f_Long ; echo "SSL CERTIFICATES" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
jq -r '.[] | {Subject: .dns_names[], Issuer: .issuer.name, Expires: .not_after, CertSHA256: .cert.sha256}' $tempdir/hostcert.json | tr -d '}"{,' |
sed 's/^ *//' | sed '/^$/d' | sed 's/C=/\nC: /g' | sed 's/ST=/\nST=/g' | sed 's/L=/\nL=/g' | sed 's/OU=/\nOU=/g' | sed 's/O=/\nO:/g' | sed 's/CN=/\nCN:/g' |
sed 's/^ *//' | sed '/^ST=/d' | sed '/^OU=/d' | sed '/^L=/d' | tr '[:space:]' ' ' | sed 's/Subject:/\n\nSUBJECT:/g' | sed 's/Expires:/\nEXPIRES:/g' |
sed 's/Issuer:/\n\nISSUER:/g' | sed 's/CertSHA256:/\nSHA256: /g' | sed 's/ O:/| O: /g' | sed 's/ CN:/| CN: /g' | sed 's/^ *//' | sed '/SHA256:/G'; fi; else
if [ $type_mx = "true" ] ; then
if [ $option_starttls = "1" ] ; then
echo | timeout 3 openssl s_client -connect $s:25 -starttls smtp -status 2>/dev/null > $tempdir/ssl_status.txt
echo | timeout 3 openssl s_client -connect $s:25 -starttls smtp 2>/dev/null |
openssl x509 -text -nameopt multiline -subject -issuer -dates -fingerprint -serial > $tempdir/x509.txt
exp=$(grep -s 'notAfter=' $tempdir/x509.txt | cut -d '=' -f 2- |  sed 's/^ *//') ; mx_port="25"
if [ -z "$exp" ]; then
echo | timeout 3 openssl s_client -connect $s:465 -starttls smtp -status 2>/dev/null > $tempdir/ssl_status.txt
echo | timeout 3 openssl s_client -connect $s:465 -starttls smtp 2>/dev/null |
openssl x509 -text -nameopt multiline -subject -issuer -dates -fingerprint -serial > $tempdir/x509.txt
mx_port="465" ; fi
exp=$(grep -s 'notAfter=' $tempdir/x509.txt | cut -d '=' -f 2- |  sed 's/^ *//')
if [ -z "$exp" ]; then
echo | timeout 3 openssl s_client -connect $s:587 -starttls smtp -status 2>/dev/null > $tempdir/ssl_status.txt
echo | timeout 3 openssl s_client -connect $s:587 -starttls smtp 2>/dev/null |
openssl x509 -text -nameopt multiline -subject -issuer -dates -fingerprint -serial > $tempdir/x509.txt
mx_port="587" ; fi
elif [ $option_starttls = "2" ] ; then
echo | timeout 3 openssl s_client -connect $s:143 -starttls imap -status 2>/dev/null > $tempdir/ssl_status.txt
echo | timeout 3 openssl s_client -connect $s:143 -starttls imap 2>/dev/null |
openssl x509 -text -nameopt multiline -subject -issuer -dates -fingerprint -serial > $tempdir/x509.txt
exp=$(grep -s 'notAfter=' $tempdir/x509.txt | cut -d '=' -f 2- |  sed 's/^ *//'); mx_port="143"
if [ -z "$exp" ]; then
echo | timeout 3 openssl s_client -connect $s:993 -starttls imap -status 2>/dev/null > $tempdir/ssl_status.txt
echo | timeout 3 openssl s_client -connect $s:993 -starttls imap 2>/dev/null |
openssl x509 -text -nameopt multiline -subject -issuer -dates -fingerprint -serial > $tempdir/x509.txt
mx_port="993" ; fi ; fi
else
echo | timeout 3 openssl s_client -connect ${s}:443 2>/dev/null -status > $tempdir/ssl_status.txt
echo | timeout 3 openssl s_client -connect ${s}:443 2>/dev/null |
openssl x509 -text -ocspid --ocsp_uri -fingerprint -serial -subject -issuer -dates -nameopt multiline | sed 's/^ *//' > $tempdir/x509.txt
exp=$(grep -s 'notAfter=' $tempdir/x509.txt | cut -d '=' -f 2- |  sed 's/^ *//')
echo | timeout 3 openssl s_client -connect ${s}:443 2>/dev/null -showcerts > $tempdir/chain.txt ; fi
exp=$(grep -s 'notAfter=' $tempdir/x509.txt | cut -d '=' -f 2- |  sed 's/^ *//')
cipher=$(sed -n '/END CERTIFICATE/,$p' $tempdir/ssl_status.txt | grep 'Cipher is' | rev | cut -d ' ' -f 1 | rev)
protocol=$(sed -n '/END CERTIFICATE/,$p' $tempdir/ssl_status.txt | grep 'Cipher is' | grep -E -o "(SSLv[23]|TLSv1(\.[0-3])?)")
verify=$(sed -n '/END CERTIFICATE/,$p' $tempdir/ssl_status.txt | grep 'Verification' | cut -d ':' -f 2- | sed 's/^ *//')
sha_1=$(grep "SHA1 Fingerprint=.*" $tempdir/x509.txt | cut -d '=' -f 2- | sed 's/^ *//')
start_date=$(grep 'notBefore=' $tempdir/x509.txt | cut -s -d '=' -f 2- | awk '{print $1,$2,$4}' | sed 's/^ *//')
ex_date=$(echo $exp | awk '{print $1,$2,$4}')
s_cc=$(sed -n '/subject=/,/commonName/p' $tempdir/x509.txt | grep -m 1 'countryName' | cut -d '=' -f 2- | sed 's/^ *//')
s_cn=$(sed -n '/subject=/,/commonName/p' $tempdir/x509.txt | grep -i -w -m 1 'commonName' | cut -d '=' -f 2- | sed 's/^ *//')
s_org=$(sed -n '/subject=/,/commonName/p' $tempdir/x509.txt | grep -i -w -m 1 'organizationName' | cut -d '=' -f 2- | sed 's/^ *//')
ca_cc=$(sed -n '/issuer=/,/commonName/p' $tempdir/x509.txt | grep -i -w -m 1 'countryName' | cut -d '=' -f 2- | sed 's/^ *//')
ca_cn=$(sed -n '/issuer=/,/commonName/p' $tempdir/x509.txt | grep -i -w -m 1 'commonName' | cut -d '=' -f 2- | sed 's/^ *//')
ca_org=$(sed -n '/issuer=/,/commonName/p' $tempdir/x509.txt| grep -i -w -m 1 'organizationName' | cut -d '=' -f 2- | sed 's/^ *//')
t_key=$(grep -i -w 'Server Temp Key' $tempdir/ssl_status.txt | cut -d ':' -f 2- | sed 's/^ *//')
serial=$(grep 'serial=' $tempdir/x509.txt | cut -d '=' -f 2- | sed 's/^ *//')
pubkey=$(grep -w -A 1 "Public Key Algorithm:" $tempdir/x509.txt | cut -d ':' -f 2- | sed 's/^ *//' | tr '[:space:]' ' ' ; echo '')
sign_algo=$(grep -w -i -m 1 "Signature Algorithm:" $tempdir/x509.txt | cut -d ':' -f 2- | sed 's/^ *//')
no_response=$(grep -s -w -i -o "no response sent"  $tempdir/ssl_status.txt | sed 's/^[ \t]*//' | sed 's/no response/no OCSP response/')
cert_status=$(grep -s -i -w 'Cert Status:' $tempdir/ssl_status.txt | sed 's/^ *//')
if [ -n "$cert_status" ] ; then
ocsp_status="$cert_status" ; else
ocsp_status="$no_response" ; fi
if [ -n "$exp" ]; then
if [ $target_type = "dnsrec" ] ; then
export mx_port
f_Long; echo -e "$s" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
echo -e "\n\nStatus:        $verify  ($start_date - $ex_date)" ; else
if [ $quiet_dump = "false" ] ; then
echo ''; f_Long ; echo "[+] SSL |  $s  |  STATUS:  $verify  " ; f_Long
echo -e "\nValid:         $start_date - $ex_date" ; else
echo -e "\n$s: Certificate found - $verify" ; fi ; fi
echo -e "\nStatus:        $verify,  $start_date - $ex_date" > $tempdir/ssl1
if [ -n "$s_org" ] ; then
echo -e "\nSubject:       $s_cn  ($s_org from $s_cc)" > $tempdir/ssl2; else
echo -e "\nSubject:       $s_cn  $s_cc" > $tempdir/ssl2; fi
if [ $ssl_details = "true" ] ; then
is_ca=$(grep -A 5 "X509v3 Basic Constraints:" $tempdir/x509.txt | grep 'CA:' | cut -d ':' -f 2- | sed 's/^ *//')
echo -e "\nIs CA:         $is_ca" >> $tempdir/ssl2 ; fi
echo -e "\nOCSP:          $ocsp_status" >> $tempdir/ssl2
echo -e "\nIssuer:        $ca_cn  ($ca_org from $ca_cc)" >> $tempdir/ssl2 ; cat $tempdir/ssl2
if [ $target_type = "dnsrec" ] ; then
echo -e "\n\nSHA-1:         $sha_1" ; echo -e "\nSerial:        $serial"
echo -e "\nCipher/Key:    $cipher | $protocol | $pubkey\n"
sed -e '/./{H;$!d;}' -e 'x;/Subject Alternative Name:/!d;' $tempdir/x509.txt | grep 'DNS:' | sed 's/DNS://g' |
sed 's/^ *//' | fmt -s -w 60 >> $tempdir/mx_altnames ; echo '' >> $tempdir/mx_altnames;  else
if [ $quiet_dump = "false" ] ; then
echo -e "\n___________________________________________________________\n" ; echo -e "Fingerprints (SHA1)\n"
host $s > $tempdir/hostip; target_ipv4=$(grep "has address" $tempdir/hostip | awk '{print $NF}' | sort -uV)
target_ipv6=$(grep "has IPv6 address" $tempdir/hostip | awk '{print $NF}' | sort -uV)
if [ -n "$target_ipv4" ] ; then
for a in $target_ipv4 ; do
echo | openssl s_client -connect $a:443 -servername $s 2>/dev/null | openssl x509 -noout -nocert -nameopt multiline -subject -fingerprint > $tempdir/sha1
coname=$(grep -i 'commonName' $tempdir/sha1 | cut -d '=' -f 2- | sed 's/^ *//')
grep "SHA1 Fingerprint=.*" $tempdir/sha1 | cut -d '=' -f 2- | sed 's/^ *//'
echo -e "CN: $coname  [$a]\n" ; done ; fi
if [ -n "$target_ipv6" ] ; then
for z in $target_ipv6 ; do
echo | openssl s_client -connect [$z]:443 -servername $s 2>/dev/null | openssl x509 -noout -nocert -nameopt multiline -subject -fingerprint > $tempdir/sha1
coname=$(grep -i 'commonName' $tempdir/sha1 | cut -d '=' -f 2- | sed 's/^ *//')
grep "SHA1 Fingerprint=.*" $tempdir/sha1 | cut -d '=' -f 2- | sed 's/^ *//'
echo -e "CN: $coname  [$z]\n" ; done ; fi ; fi
echo -e "___________________________________________________________\n" > $tempdir/ssl3
echo -e "Cipher:        $cipher | $protocol\n" >> $tempdir/ssl3
echo -e "TempKey:       $(grep -i -w 'Server Temp Key' $tempdir/ssl_status.txt | cut -d ':' -f 2- | sed 's/^ *//')" >> $tempdir/ssl3
echo -e "PubKey:        $pubkey" >> $tempdir/ssl3
echo -e "Signature:     $sign_algo" >> $tempdir/ssl3
echo -e "\nSerial:        $serial" >> $tempdir/ssl3 ; cat $tempdir/ssl3
if [ $ssl_details = "true" ] ; then
echo -e "___________________________________________________________\n"
echo -e "Key Usage:     $(grep -A 1 'Key Usage:' $tempdir/x509.txt | grep -v 'Key Usage' | head -1)"
echo -e "               $(grep -A 1 'Extended Key Usage:' $tempdir/x509.txt | grep -v 'Key Usage' | tail -1)"
echo -e "___________________________________________________________\n" ; echo -e "OCSP:\n"
grep -s -w -i -o "no response sent"  $tempdir/ssl_status.txt | sed 's/^[ \t]*//'
grep -s -i -w 'OCSP Response Status:' $tempdir/ssl_status.txt | sed 's/^[ \t]*//'
grep -s -i -w 'Responder Id:' $tempdir/ssl_status.txt | sed 's/^[ \t]*//'
grep -s -i -w 'Cert Status:' $tempdir/ssl_status.txt | sed 's/^ *//'
grep -s "OCSP - URI" $tempdir/x509.txt | cut -d ':' -f 2- | sed 's/^ *//'
grep -s 'Subject OCSP hash:' $tempdir/x509.txt | sed 's/^ *//'
grep -s 'Public key OCSP hash:' $tempdir/x509.txt | sed 's/^ *//' ; fi
echo '' > $outdir/CERT.${s}.txt ; f_Long >> $outdir/CERT.${s}.txt
echo "[+] $s | CERTIFICATE FILE DUMP | $(date)" >> ${outdir}/CERT.${s}.txt ; f_Long >> $outdir/CERT.${s}.txt
cat $tempdir/ssl1 >> $outdir/CERT.${s}.txt; cat $tempdir/ssl2 >> ${outdir}/CERT.${s}.txt; cat $tempdir/ssl3 >> ${outdir}/CERT.${s}.txt
if [ $quiet_dump = "false" ] ; then
echo -e "\n___________________________________________________________\n"
echo -e "Subject AltNames\n"
sed -e '/./{H;$!d;}' -e 'x;/Subject Alternative Name:/!d;' $tempdir/x509.txt | grep 'DNS:' | sed 's/DNS://g' | sed 's/^ *//' | fmt -s -w 60 ; fi
echo -e "\n___________________________________________________________\n" >> $outdir/CERT.${s}.txt
cat $tempdir/x509.txt | grep -E "serial=|SHA1 Fingerprint=" | sed 's/serial=/\nSerial:\n/' |
sed 's/SHA1 Fingerprint=/SHA1 Fingerprint:\n/' >> $outdir/CERT.${s}.txt
echo -e "\n___________________________________________________________\n" >> $outdir/CERT.${s}.txt
sed -n '/Certificate chain/,/Server certificate/p' $tempdir/chain.txt | sed 's/s:/Holder: /g' | sed 's/i:/Issuer: /g' | sed '/END/G' |
sed '/BEGIN/{x;p;x}' | sed '$d' >> ${outdir}/CERT.${s}.txt
echo '' >> ${outdir}/CERT.${s}.txt; sed -n '/X509v3 extensions:/,/SHA1/p' $tempdir/x509.txt |
sed '$d' | sed '/Subject Key Identifier:/{x;p;x;}' | sed '/Policies:/{x;p;x;}' | sed '/Subject OCSP/{x;p;x;}' |
sed '/SCTs/{x;p;x;}' | sed '/SHA1/d' | sed '/Signature Algorithm:/{x;p;x;G}' | sed '/Timestamp:/{x;p;x;}' |
sed '/Constraints:/{x;p;x;}' | sed '/extensions:/{x;p;x;}' | sed '/Policies:/{x;p;x;}' |
sed '/Alternative Name:/{x;p;x;G}' >> ${outdir}/CERT.${s}.txt ; fi
if [ $quiet_dump = "false" ] ; then
if ! [ $option_testSSL = "0" ] ; then
f_testSSL "${s}" ; fi
if ! [ $option_sslscan = "0" ] ; then
f_SSLSCAN "${s}" ; fi
elif [ $quiet_dump = "true" ] && [ $ssl_details = "true" ] ; then
f_SSLSCAN "${s}"; f_testSSL "${s}" ; fi; else
echo -e "\nNo certificate found for $s.\n" ; fi ; fi ; echo ''
}

#********************** IP REPUTATION & BOGON CHECK ***********************
f_BLOCKLISTS(){
local s="$*" ; reverse=$(echo $s | awk -F'.' '{printf $4 "." $3 "." $2 "." $1}')
for i in ${blocklists} ; do
in_list="$(dig @1.1.1.1 +short -t a ${reverse}.${i}.)"
if [[ $in_list ]]; then
echo -e "YES (${in_list}) | ${i}" ; else
echo -e "NO | ${i}" ; fi ; done
}
f_blocklistCHECK() {
local s="$*"
for i in $(cat $s | sort -u -V) ; do
if [ $target_type = "net" ] ; then
bl_entries=$(f_BLOCKLISTS "${i}" | grep -v "NO")
if echo $bl_entries | grep -q -E "YES"; then
echo -e "\n !!! $i !!! \n" ; echo -e "\n\n$i\n" >> $tempdir/listings
echo "$bl_entries" | grep -v "NO" | tee -a $tempdir/listings
echo -e "\n" | tee -a $tempdir/listings ; else
echo -e "+ $i  OK\n" ; fi ; else
bl_entries=$(f_BLOCKLISTS "${i}" | grep -v "NO")
if echo $bl_entries | grep -q -E "YES"; then
echo -e "\n+ DNS Blocklists:      [$i]"
echo "$bl_entries" | grep -v "NO" | sed 's/^/                       /'; echo ''; else
echo -e "+ DNS Blocklists:      Not listed [$i]" ; fi ; fi ; done
}
f_BOGON() {
local s="$*" ; reverse=$(echo $s | awk -F'.' '{printf $4 "." $3 "." $2 "." $1}')
query="$(dig @9.9.9.9 +short -t a ${reverse}.bogons.cymru.com.)"
if [[ $query ]]; then
bogon="TRUE" ; else
bogon="FALSE" ; fi ; export bogon
}
f_TOR1() {
local s="$*" ; reverse=$(echo $s | awk -F'.' '{printf $4 "." $3 "." $2 "." $1}')
is_tor=$(dig @9.9.9.9 +short -t a $(echo $s | awk -F'.' '{printf $4 "." $3 "." $2 "." $1}').tor.dan.me.uk.)
if [[ $is_tor ]]; then
echo "TOR: true (${is_tor})" ; else
echo "TOR: false" ; fi
}
f_TOR2() {
local s="$*" ; reverse=$(echo $s | awk -F'.' '{printf $4 "." $3 "." $2 "." $1}')
is_tor=$(dig @9.9.9.9 +short -t a $(echo $s | awk -F'.' '{printf $4 "." $3 "." $2 "." $1}').tor.dan.me.uk.)
if [[ $is_tor ]]; then
echo "+ TOR Node:            true (${is_tor}) [$s]"; else
echo "+ TOR Node:            false [$s]" ; fi
}
f_SPAMHAUS(){
local s="$*" ; reverse=$(echo $s | awk -F'.' '{printf $4 "." $3 "." $2 "." $1}')
listed=$(dig @1.1.1.1 +short -t a ${reverse}.zen.spamhaus.org.)
if [[ $listed ]]; then
listings=$(echo "$listed" | sed 's/127.0.0.2/SPAM Service\/Operation/' | sed 's/127.0.0.3/Direct snowshoe spam source/' |
sed 's/127.0.0.4/3rd party exploits (e.g.proxies, trojans, etc)/' | sed 's/127.0.0.5/3rd party exploits (e.g.proxies, trojans, etc)/' |
sed 's/127.0.0.10/End-user Non-MTA IP addresses set by ISP/' | sed 's/127.0.0.11/End-user Non-MTA IP addresses set by ISP/' | tr '[:space:]' ' ')
echo -e "+ Spamhaus ZEN:        $listings" ; else
echo -e "+ Spamhaus ZEN:        Not listed [$s]" ; fi
}
f_bSCATTERER(){
local s="$*"; backs=$(dig @9.9.9.9 +short -t a $(echo $s | awk -F'.' '{printf $4 "." $3 "." $2 "." $1}').ips.backscatterer.org.)
if [[ $backs ]]; then
echo "+ backscatterer.org:   $s is LISTED on ips. backscatter.org" ; else
echo "+ backscatterer.org:   Not listed [$s]" ; fi
}
f_DBL(){
local s="$*" ; dbl_listed="$(dig @1.1.1.1 +short ${s}.dbl.spamhaus.org)"
if [[ $dbl_listed ]]; then
is_listed="$s is listed in Spamhaus DBL; return code: ${dbl_listed}" ; else
is_listed="not listed in spamhaus.org Domain BL" ; fi
echo -e "\nDBL:          $is_listed"
}
f_threatSUMMARY(){
local s="$*" ; incidents=$(jq -r '.ip.count?' $tempdir/iscip.json | sed '/null/d')
if [ -n "$incidents" ] ; then
echo  -e "___________________________________________________\n"
if [ $domain_enum = "false" ] ; then
echo -e  "\n+ INTERNET STORM CENTER (SANS) \n" ; else
echo -e "+ $s\n" ; fi
echo "IP:                    $(jq -r '.ip.number?' $tempdir/iscip.json)"
echo "Incidents:             $(jq -r '.ip.count?' $tempdir/iscip.json)"
echo "Attacks:               $(jq -r '.ip.attacks?' $tempdir/iscip.json)"
echo "Time:                  $(jq -r '.ip.mindate?' $tempdir/iscip.json) - $(jq -r '.ip.maxdate' $tempdir/iscip.json)"
echo "Updated:               $(jq -r '.ip.mindate?' $tempdir/iscip.json)"
curl -s "https://isc.sans.edu/api/ipdetails/${s}?json" > $tempdir/ipdetails.json
jq -r '.[] | { Date: .date, Time: .time, SourcePort: .sourceport, TargetPort: .targetport, Protocol: .protocol, Flags: .flags}' $tempdir/ipdetails.json |
tr -d '},\"{' | sed 's/^ *//' | sed '/^$/d' | sed 's/Date:/Date:       /g' | sed 's/Time:/Time:       /g' | sed 's/Protocol: 6/Protocol: TCP/g' |
sed 's/Protocol: 17/Protocol: UDP/g' | sed 's/Protocol:/Protocol:   /g' |
sed '/Flags:/G' | sed 's/Flags:/Flags:      /g' | sed 's/SourcePort:/SourcePort: /g' | sed 's/TargetPort:/TargetPort: /g' > $tempdir/attacks
if [ -f $tempdir/attacks ] ; then
echo -e "\n\nRecent Incidents (Times, Ports)\n"
tail -49 $tempdir/attacks ; rm $tempdir/attacks ; fi
echo  -e "___________________________________________________\n" ; else
echo "+ I.net Storm Center:  No results for $s"; fi
}
f_projectHONEYPOT(){
local s="$*" ; rev=$(echo $s | awk -F'.' '{printf $4 "." $3 "." $2 "." $1}')
if [ -n "$honeykey" ] ; then
response=$(dig +short ${honeykey}.${rev}.dnsbl.httpbl.org)
if [[ -z "$response" ]]; then
echo "+ Project Honeypot:    No results for $s" ; else
echo -e "\n\n* PROJECT HONEYPOT \n"
last_seen=$(echo "$response" | awk -F'.' '{print $2}') ; score=$(echo "$response" | awk -F'.' '{print $3}')
category=$(echo "$response" | awk -F'.' '{print $4}')
if [ $category = "0" ] ; then
agent_cat="Category:                  Search Engine"
elif [ $category = "1" ] ; then
agent_cat="Category:                  Suspicious"
elif [ $category = "2" ] ; then
agent_cat="Category:                  Harvester"
elif [ $category = "4" ] ; then
agent_cat="Category:                  Comment Spammer"
elif [ $category = "5" ] ; then
agent_cat="Category:                  Suspicious & Comment Spammer"
elif [ $category = "6" ] ; then
agent_cat="Category:                  Harvester & Comment Spammer" ; fi
if [ $category = "0" ] ; then
if [ $score = "0" ]; then
third_octett="Agent:                  Undocumented Searchengine"
elif [ $score = "3" ] ; then
third_octett="Agent:                  Baidu"
elif [ $score = "5" ] ; then
third_octett="Agent:                  Google"
elif [ $score = "8" ] ; then
third_octett="Agent:                  Yahoo" ; else
third_octett="Agent:                  Searchengine (Miscellaneous)" ; fi ; fi
if ! [ $category = "0" ] ; then
third_octett="Threat Score:   $score" ; fi
echo "$agent_cat" ; echo "$third_octett" ; echo -e "Last Seen:      $last_seen  day(s) ago\n" ; fi ; else
echo -e "\n+ Project Honeypot:    Please provide API key; for more information run option 'h' (help)" ; fi
}
f_greyNOISE(){
local s="$*"; curl -m5 -s "https://api.greynoise.io/v3/community/$s" > $tempdir/gn.json
last_seen=$(jq -r '.last_seen' $tempdir/gn.json | sed '/null/d')
message=$(jq -r '.message' $tempdir/gn.json)
if [ -n "$last_seen" ] ; then
echo -e "\n+ GREYNOISE COMMUNITY API\n"
echo "IP:                    $(jq -r '.ip' $tempdir/gn.json)"
echo "Noise:                 Observed scanning the internet: $(jq -r '.noise' $tempdir/gn.json)"
echo "Last Seen:             $(jq -r '.last_seen' $tempdir/gn.json)"
echo "Classification:        $(jq -r '.classification' $tempdir/gn.json)"
echo "Rule It Out (RIOT):    $(jq -r '.riot' $tempdir/gn.json)" ; else
message_out=$(echo $message | sed 's/IP not observed scanning the internet or contained in RIOT data set./Not listed as scanner or in RIOT data set/')
echo "+ GreyNoise:           $message_out [$(jq -r '.ip' $tempdir/gn.json)]" ; fi
}
f_forumSPAM(){
local s="$*"
curl -s "http://api.stopforumspam.org/api?ip=${s}&json&badtorexit" > $tempdir/forum.json
last_seen=$(jq -r '.ip.lastseen' $tempdir/forum.json | sed '/null/d')
if  [ -n "$last_seen" ] ; then
echo -e "\n\n+ STOP FORUM SPAM\n"
echo "Last Seen:             $(jq -r '.ip.lastseen' $tempdir/forum.json)"
echo "Frequency:             $(jq -r '.ip.frequency' $tempdir/forum.json)"
echo "Appears:               $(jq -r '.ip.appears' $tempdir/forum.json)"
echo "Country:               $(jq -r '.ip.country' $tempdir/forum.json)"
echo "Torexit:               $(jq -r '.ip.torexit' $tempdir/forum.json)"
echo "Confidence:            $(jq -r '.ip.confidence' $tempdir/forum.json)" ; else
echo "+ Stop Forum SPAM:     No results for $s" ; fi
}
f_IP_REPUTATION(){
local s="$*"
if [ $domain_enum = "true" ] ; then
echo  -e "___________________________________________________\n" ; fi
f_projectHONEYPOT "${s}"; f_forumSPAM "${s}" ; f_SPAMHAUS "${s}"
if [ $target_type = "web" ] && [ $domain_enum = "false" ]; then
f_TOR2 "${s}" ; fi
echo $s > $tempdir/bl_check; f_blocklistCHECK "$tempdir/bl_check"
if [ $target_type = "default" ] ; then
f_threatSUMMARY "${s}" ; fi ; f_greyNOISE "${s}"
}
f_HOST_BL_CHECK(){
local s="$*" ; echo  -e "________________________________________________\n\n"
f_bSCATTERER "${s}" ; f_TOR2 "${s}" ; f_projectHONEYPOT "${s}"; f_SPAMHAUS "${s}" ; f_forumSPAM "${s}"
echo $s > $tempdir/bl_check; f_blocklistCHECK "$tempdir/bl_check" ; f_greyNOISE "${s}"
}

#********************** ABUSE CONTACT FINDER ***********************
f_abuse_cFINDER(){
local s="$*" ; echo ''
if echo $s | grep -q -i "as" ; then
asn=$(echo $s | sed 's/[Aa][Ss]//' | sed 's/[Aa][Ss] //' | tr -d ' ')
f_AS_ABUSEMAIL "${asn}" ; echo -e "\nAS $asn Abuse Contact:  $asabuse_c" ; else
curl -m 5 -s "https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=${s}" > $tempdir/ac.json
rir=$(jq -r '.data.authoritative_rir' $tempdir/ac.json) ; abuse_mbox=$(jq -r '.data.abuse_contacts[]' $tempdir/ac.json | tr '[:space:]' ' ' ; echo '')
if [ -n "$abuse_mbox" ] ; then
echo -e "\n[@]:         $abuse_mbox (source: RipeStat)\n" ; else
if [ $rir = "arin" ] || [ $rir = "lacnic" ] ; then
whois -h whois.${rir}.net $s > $tempdir/whois ; else
whois -h whois.${rir}.net -- "--no-personal $s" | sed 's/^ *//' > $tempdir/whois; fi 
abuse_mbox=$(grep -E -a -s -m 1 "^OrgAbuseEmail:|^% Abuse|^abuse-mailbox:|^e-mail:|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/whois |
grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b")
if [ -z "$abuse_mbox" ] ; then
abuse_mbox=$(grep -E -o -m 2 "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/whois); fi
echo -e "\n[@]:         $abuse_mbox (source: whois.$rir.net)\n" ; fi ; fi
}

#********************** DNS RECORDS & SUBDOMAINS ***********************
f_DNS_REC(){
local s="$*" ; srv_rec='' ; nss='' ; mxs=''
touch $tempdir/ips6.list; echo ''; f_Long; echo "[+]  DNS RECORDS  |  $s"; f_Long
if [ -f $tempdir/rec_ips.list ] ; then
rm $tempdir/rec_ips.list ; fi
if [ $option_connect = "0" ] ; then
curl -s https://api.hackertarget.com/dnslookup/?q=${s} > $tempdir/dns.txt
grep "^A" $tempdir/dns.txt | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' |
tee -a $tempdir/ip4.list >> $tempdir/ips.list
echo -e "\nA & AAAA\n________\n" ; grep -E "^A|^AAAA" $tempdir/dns.txt | awk '{print $NF}'
if cat $tempdir/dns.txt | grep -q -E "^MX"; then
echo -e "\n\nMail (MX) Servers\n_________________\n"
grep -E "MX" $tempdir/dns.txt | cut -d ':' -f 2- | sed 's/^ *//' ; echo '' ; fi
echo -e "\nName Servers\n____________\n"
grep -E "^NS" $tempdir/dns.txt | cut -d ':' -f 2- | sed 's/^ *//'
echo -e "\n\nStart of Authority \n___________________\n"
grep -E "^SOA" $tempdir/dns.txt | cut -d ':' -f 2- | sed 's/^ *//' ; echo '' 
if cat $tempdir/dns.txt | grep -q -E "^TXT"; then
echo -e "\nTXT Records \n____________\n"
grep "^TXT" $tempdir/dns.txt | sed '/TXT :/{x;p;x;}' | cut -d ' ' -f 3- | fmt -s -w 80 ; echo '' ; fi ; f_Long ; echo '' 
for i in $(grep -E "^A|AAAA" $tempdir/dns.txt | cut -d ' ' -f 3) ; do
f_hostSHORT "${i}" ; echo '' ; done
if cat $tempdir/dns.txt | grep -q -E "^MX"; then
for m in $(grep -E "^MX" $tempdir/dns.txt | rev | cut -d '.' -f 2- | cut -d ' ' -f 1 | rev); do 
f_hostSHORT "${m}"; echo '' ; done > $tempdir/mx_info ; cat $tempdir/mx_info 
egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/mx_info  | tee -a $tempdir/ips.list > $tempdir/mxip.list ; fi
for n in $(grep -E "^NS" $tempdir/dns.txt | rev | cut -d '.' -f 2- | cut -d ' ' -f 1 | rev); do 
f_hostSHORT "${n}" ; done > $tempdir/ns_info; cat $tempdir/ns_info
egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/ns_info | tee -a $tempdir/ips.list >> $tempdir/nsip.list
echo '' ; f_Long; f_whoisTABLE "$tempdir/ips.list" ; cat $tempdir/whois_table.txt | cut -d '|' -f -5 | sed '/^$/d' |
sed '/NET NAME/G' ; echo -e "\n"
asns=$(cut -d '|' -f 1 $tempdir/whois_table.txt | sed '/AS/d' | sed '/NA/d' | sed '/^$/d' | tr -d ' ' | sort -uV)
for as in $asns ; do
asn=$(dig +short as$as.asn.cymru.com TXT | tr -d "\"" | sed 's/^ *//' | cut -d '|' -f 1,5 | sed 's/ |/,/g') ; echo -e "AS $asn" ; done ; echo -e "\n"; else
if [ $domain_enum = "true" ] ; then
rfc1912="true" ; fi
if [ $option_ttl = "2" ] ; then
ttl="+ttlunits" ; else
ttl="+ttlid" ; fi
echo -e "\nDOMAIN HOST\t\t\t${s}\n"
dig ${dig_array[@]} ${ttl} $s | grep -w 'A' | tee $tempdir/hostsA.list | awk '{print $2,$3,$4}' | sed 's/ /\t\t/g'
dig aaaa ${dig_array[@]} ${ttl} $s | grep -w 'AAAA' | tee $tempdir/hostsAAAA.list | awk '{print $2,$3,$4}' | sed 's/ /\t\t/g'
egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/hostsA.list | tee $tempdir/rec_ips.list >> $tempdir/ips.list
if [ -f $tempdir/hostsAAAA.list ] ; then
awk '{print $NF}' $tempdir/hostsAAAA.list > $tempdir/rec_ips6.list; fi
echo '' ; f_MX "${s}" ; echo '' ; f_Long; f_NS "${s}"
srv_rec=''; txt_rec=$(dig +short txt ${s})
echo "$txt_rec" | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}' >> $tempdir/txt_nets
txt_ips=$(echo "$txt_rec" | egrep -o -v '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}' |
egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
if [ -n "$txt_ips" ] ; then
echo "$txt_ips" | tee $tempdir/txt_ip.list >> $tempdir/rec_ips.list ; fi
srv_rec=$(nmap -Pn -sn --script dns-srv-enum --script-args dns-srv-enum.domain=$s 2>/dev/null | grep '|' | sed '/dns-srv-enum/d' |
sed '/Active Directory/{x;p;p;x;}' | sed '/APT/{x;p;p;x;}' | sed '/Autodiscover/{x;p;p;x;}' | sed '/Kerberos/{x;p;p;x;}' |
sed '/LDAP/{x;p;p;x;}' | sed '/Matrix/{x;p;p;x;}' | sed '/Minecraft/{x;p;p;x;}' | sed '/Mumble/{x;p;p;x;}' | sed '/SIP/{x;p;p;x;}' |
sed '/SMTP/{x;p;p;x;}' | sed '/POP/{x;p;p;x;}' | sed '/IMAP/{x;p;p;x;}' | sed '/TeamSpeak/{x;p;p;x;}' | sed '/XMPP/{x;p;p;x;}' |
sed '/prio/{x;p;x;}' | tr -d '|_' | sed 's/^ *//')
if [ -n "$srv_rec" ] ; then
srv_hosts=$(echo "$srv_rec" | grep -E "*./tcp|*./udp" | awk '{print $NF}' | sort -u)
for h in $srv_hosts ; do
dig ${dig_array[@]} ${h} >> $tempdir/srv ; done
egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/srv | sort -uV | tee -a $tempdir/txt_ip.list >> $tempdir/rec_ips.list ; fi
if [ $rfc1912 = "true" ] || [ $domain_enum = "true" ] ; then
f_RFC1912 "${s}" ; else
echo '' ; f_Long ; fi
if [ -f $tempdir/mx4.list ] ; then
echo -e "\n* Checking MX records for known backscatterers ...\n\n"
for i in $(egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/mx4.list | sort -uV) ; do
f_bSCATTERER "${i}" ; done ; echo '' ; f_Long ; fi
f_whoisTABLE "$tempdir/rec_ips.list" ; cat $tempdir/whois_table.txt | cut -d '|' -f -5 | sed '/^$/d' | sed '/NET NAME/G' ; echo ''
if [ $domain_enum = "false" ] ; then
asns=$(cut -d '|' -f 1 $tempdir/whois_table.txt | grep -E -v "AS|NA" | sed '/^$/d' | tr -d ' ' | sort -uV)
echo -e "___________________________________________________________\n"
for as in $asns ; do
asn=$(dig +short as$as.asn.cymru.com TXT | tr -d "\"" | sed 's/^ *//' | cut -d '|' -f 1,5 | sed 's/ |/,/g'); echo -e "AS $asn"; done; echo ''; fi
if [ -n "$txt_rec" ] ; then
f_Long; echo -e "\nTXT RECORDS\n"; echo "$txt_rec" | sed '/\"/{x;p;x;}' | fmt -s -w 80 ; fi
if [ -f $tempdir/srv ] ; then
echo ''; f_Long; echo -e "\nSRV RECORDS"; echo "$srv_rec"; echo -e "\n__________\n"
cat $tempdir/srv ; rm $tempdir/srv ; fi
if [ $domain_enum = "false" ] ; then
if [ $option_ttl = "3" ] ; then
ttl="+ttlunits" ; f_TTL_READABLE "${s}" ; fi ; fi ; f_cleanupDNS ; fi
}
f_MX(){
local s="$*"; dig mx ${dig_array[@]} ${ttl} ${s} > $tempdir/mxservers.list
mxs=$(awk '{print $NF}' $tempdir/mxservers.list) ; echo -e "\nMX SERVERS"
for mx in $mxs; do
echo '' ; grep -w -m 1 "$mx" $tempdir/mxservers.list | awk '{print $2,$3,$4"_"$5}' | sed 's/ /\t\t/g' | sed 's/_/ /g'
dig a ${dig_array[@]} ${ttl} $mx | grep -w 'A' | tee -a $tempdir/mx4.list | awk '{print $2,$3,$4}' | sed 's/ /\t\t/g'
dig aaaa ${dig_array[@]} ${ttl} $mx | grep -w 'AAAA' | tee -a $tempdir/mx6.list | awk '{print $2,$3,$4}' | sed 's/ /\t\t/g'; done
cat $tempdir/mx4.list >> $tempdir/mx_ipv4.list
egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/mx4.list | tee -a $tempdir/rec_ips.list >> $tempdir/ips.list
if [ -f $tempdir/mx6.list ] ; then
cat $tempdir/mx6.list >> $tempdir/mx_ipv6.list; awk '{print $NF}' $tempdir/mx6.list >> $tempdir/rec_ips6.list; rm $tempdir/mx6.list ; fi
}
f_NS(){
local s="$*"; dig ns ${dig_array[@]} ${ttl} $s > $tempdir/nservers.list
nss=$(awk '{print $NF}' $tempdir/nservers.list); echo -e "NAME SERVERS"
for ns in $nss ; do
echo '' ; grep -w "${ns}" $tempdir/nservers.list | awk '{print $2,$3,$4}' | sed 's/ /\t\t/g'
dig ${dig_array[@]} ${ttl} $ns | grep -w 'A' | tee -a $tempdir/ns4.list | awk '{print $2,$3,$4}' | sed 's/ /\t\t/g'
dig aaaa ${dig_array[@]} ${ttl} $ns | grep -w 'AAAA' | tee -a $tempdir/ns6.list | awk '{print $2,$3,$4}' | sed 's/ /\t\t/g'; done
egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/ns4.list | tee -a $tempdir/rec_ips.list >> $tempdir/ips.list
cat $tempdir/ns4.list >> $tempdir/ns_ipv4.list
if [ -f $tempdir/ns6.list ] ; then
cat $tempdir/ns6.list >> $tempdir/ns_ipv6.list
awk '{print $NF}' $tempdir/ns6.list >> $tempdir/rec_ips6.list
rm $tempdir/ns6.list ; fi
ns_hosts=$(awk '{print $NF}' $tempdir/nservers.list)
for n in $ns_hosts ; do
bindvers=$(dig @${n} version.bind txt chaos +norecurse +noedns +short | tr -d '"' | sed 's/^ *//')
if [ -n "$bindvers" ] ; then
echo -e "\n$n" ; echo -e "\t\t\t$bindvers" ; fi ; done > $tempdir/version_bind
if [ -f $tempdir/version_bind ] ; then
echo -e "\n\nVERSION.BIND"
if [[ $(cat $tempdir/version_bind | wc -w) -lt 2 ]] ; then
echo -e "\nNo response"; fi
cat $tempdir/version_bind ; rm $tempdir/version_bind; fi
echo ''; f_Long; echo -e "START OF AUTHORITY\n\n"; dig soa +noall +answer +multiline ${s} > $tempdir/soa.txt
dig soa +noall +answer +noclass +ttlid ${s} | awk '{print $2,$3,$4,$5}' | sed 's/ /\t/g' ; echo ''
grep -E "; serial|; refresh|; retry|; expire|; minimum" $tempdir/soa.txt | awk '{print $3":",$1,$4,$5,$6,$7}' | sed 's/:/: /g' |
sed 's/serial:/serial: /' | sed 's/retry:/retry:  /' | sed 's/expire:/expire: /' | sed '/serial:/{x;p;x;G}'
if [ $option_dns_details = "y" ] ; then
echo -e "\n\nSOA RECORD CONSISTENCY CHECK\n"; dig +short +nssearch $s | awk '{print $1,$2,$4,$11}' | sed 's/ /\t/g'; fi
}
f_TTL_READABLE(){
local s="$*"; ttl="+ttlunits" ; dig mx ${dig_array[@]} ${ttl} $s > $tempdir/mx_servers.list
dig ns ${dig_array[@]} ${ttl} $s > $tempdir/ns_servers.list
echo ''; f_Long ; echo -e "$s (TTL - HUMAN READABLE)\n"
echo -e "\nDOMAIN HOST\t\t\t${s}\n"
dig ${dig_array[@]} ${ttl} $s | grep -w 'A' | awk '{print $2,$3,$4}' | sed 's/ /\t\t/g'
dig aaaa ${dig_array[@]} ${ttl} $s | grep -w 'AAAA' | awk '{print $2,$3,$4}' | sed 's/ /\t\t/g'
mx_s=$(awk '{print $NF}' $tempdir/mxservers.list) ; echo -e "\n\nMX SERVERS\n"
for mx in $mx_s; do
echo '' ; grep -w -m 1 "$mx" $tempdir/mx_servers.list | awk '{print $2,$3,$4"_"$5}' | sed 's/ /\t\t/g' | sed 's/_/ /g'
dig a ${dig_array[@]} ${ttl} $mx | grep -w 'A' | awk '{print $2,$3,$4}' | sed 's/ /\t\t/g'
dig aaaa ${dig_array[@]} ${ttl} $mx | grep -w 'AAAA' | awk '{print $2,$3,$4}' | sed 's/ /\t\t/g'; done
ns_s=$(awk '{print $NF}' $tempdir/ns_servers.list); echo -e "\n\nNAME SERVERS\n"
for ns in $ns_s ; do
echo '' ; grep -w -m 1 "${ns}" $tempdir/ns_servers.list | awk '{print $2,$3,$4}' | sed 's/ /\t\t/g'
dig ${dig_array[@]} ${ttl}  $ns | grep -w 'A' | awk '{print $2,$3,$4}' | sed 's/ /\t\t/g'
dig aaaa ${dig_array[@]} ${ttl} $ns | grep -w 'AAAA' | awk '{print $2,$3,$4}' | sed 's/ /\t\t/g'; done
}
f_dnsREC_II(){
local s="$*"; echo '' ; f_Long; echo -e "NSEC RECORDS\n\n"; f_NSEC_DOMAIN ${s}
if [ $domain_enum = "true" ] ; then
if ! [ "$s" = "$target_host_dom" ] ; then
echo ''; f_NSEC_DOMAIN "${target_host_dom}" ; echo '' ; fi ; fi ; f_NSEC_NS ; f_PTR
}
f_NSEC_DOMAIN(){
local s="$*"; host -t nsec ${s} 1.1.1.1 | tail -1 | fmt -s -w 80
host -t nsec3 ${s} 1.1.1.1 | tail -1 | fmt -s -w 80
}
f_NSEC_NS(){
list_nservers=$(awk -F' ' '{print $NF}' $tempdir/nservers.list | sed 's/.$//' | sort -u -V)
for nsurl  in $list_nservers ; do
nsec=$(host -t nsec ${nsurl} 1.1.1.1 | tail -1 | fmt -s -w 80); nsec3=$(host -t nsec3 ${nsurl} 1.1.1.1 | tail -1 | fmt -s -w 80)
echo '' ; echo "$nsec" ; echo "$nsec3" ; done ; echo '' ; f_Long
}
f_cleanupDNS(){
if [ -f $tempdir/mx4.list ] ; then
rm $tempdir/mx4.list; fi 
if [ -f $tempdir/ns4.list ] ; then
rm $tempdir/ns4.list ; fi 
if [ -f $tempdir/mx6.list ] ; then
rm $tempdir/mx6.list ; fi
if [ -f $tempdir/ns6.list ] ; then
rm $tempdir/ns6.list ; fi
}
f_PTR(){
echo -e "\nPTR RECORDS\n\n"
for a in $(cat $tempdir/rec_ips.list | sort -uV); do
ptr=$(host $a ${nsserv} | grep -E "name pointer" | rev | cut -d ' ' -f 1 | rev | tr '[:space:]' ' ')
if [ -n "$ptr" ] ; then
echo -e "$a \n     $ptr\n" ; else
echo -e "$a \n     no PTR record\n" ; fi ; done
dnsrec_v6=$(cat $tempdir/rec_ips6.list | sort -uV)
if [ -n "$dnsrec_v6" ] ; then
for z in $dnsrec_v6 ; do
ptr=$(host $z ${nsserv} | grep -E "name pointer" | rev | cut -d ' ' -f 1 | rev | tr '[:space:]' ' ')
if [ -n "$ptr" ] ; then
echo -e "$z \n     $ptr\n" ; else
echo -e "$z \n     no PTR record\n" ; fi ; done ; fi
}
f_DNSdetails(){
echo ''; egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/mx_ipv4.list | sort -uV > $tempdir/mxip.list
egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/ns_ipv4.list | sort -uV > $tempdir/nsip.list
awk '{print $NF}' $tempdir/mx_ipv6.list | sort -uV > $tempdir/m6.list
awk '{print $NF}' $tempdir/ns_ipv6.list | sort -uV > $tempdir/n6.list
if [ $domain_enum = "false" ] ; then
host $x > $tempdir/hostip; hostA=$(grep "has address" $tempdir/hostip | awk '{print $NF}')
hostAAAA=$(grep "has IPv6 address" $tempdir/hostip | awk '{print $NF}') ; fi
if [ $domain_enum = "true" ] ; then
f_Long ; echo "[+]  MX  |  SSL STATUS"
mx_servers=$(cat $tempdir/mx_ipv4.list | awk -F' ' '{print $1}' | sed 's/.$//' | sort -uV)
for m in $mx_servers ; do
f_certINFO "${m}"  ; done ; fi
for mxip in $(cat $tempdir/mxip.list | sort -uV) ; do
mxurl=$(grep ${mxip} $tempdir/mx_ipv4.list | awk -F' ' '{print $1}' | sort -u | tr '[:space:]' ' ' | fmt -s -w 100 ; echo '')
record_type="MX"; record_ip="$mxip"; record_nme="$mxurl"; f_recordINFO "${mxip}" ; echo '' ; done
if [ $domain_enum = "false" ] ; then
if [ -n "$hostA" ] ; then
for a in $hostA ; do
record_type="A"; record_ip="$a"; record_nme="$x"; f_recordINFO "${a}" ; echo '' ; done ; fi ; fi
if [ -f $tempdir/mx_ipv6.list ] ; then
awk '{print $NF}' $tempdir/mx_ipv6.list | sort -uV > $tempdir/m6.list
for mxip in $(cat $tempdir/m6.list | sort -uV) ; do
mxurl=$(grep ${mxip} $tempdir/mx_ipv6.list | awk -F' ' '{print $1}' | sort -u | tr '[:space:]' ' ' | fmt -s -w 100 ; echo '')
record_type="MX"; record_ip="$mxip"; record_nme="$mxurl"; f_recordINFO "${mxip}" ; done ; fi
for nsip in $(cat $tempdir/nsip.list | sort -uV) ; do
nsurl=$(grep ${nsip} $tempdir/ns_ipv4.list | awk -F' ' '{print $1}' | sort -u | tr '[:space:]' ' ' | fmt -s -w 100 ; echo '')
record_type="NS"; record_ip="$nsip"; record_nme="$nsurl"; f_recordINFO "${nsip}"; echo '' ; done
if [ -f $tempdir/ns_ipv6.list ] ; then
awk '{print $NF}' $tempdir/ns_ipv6.list | sort -uV > $tempdir/n6.list
for nsip in $(cat $tempdir/n6.list | sort -uV) ; do
nsurl=$(grep ${nsip} $tempdir/ns_ipv6.list | awk -F' ' '{print $1}' | sort -u | tr '[:space:]' ' ' | fmt -s -w 100 ; echo '')
record_type="NS"; record_ip="$nsip"; record_nme="$nsurl"; f_recordINFO "${nsip}" ; echo '' ; done ; fi
if [ $domain_enum = "false" ] ; then
if [ -n "$hostAAAA" ] ; then
for z in $hostAAAA ; do
record_type="AAAA"; record_ip="$z"; record_nme="$x"; f_recordINFO "${z}" ; echo '' ; done ; fi ; fi
}
f_RFC1912(){
local s="$*" ; soa=$(dig soa +short $s); soa_host=$(echo "$soa" | cut -d ' ' -f 1)
echo '' ; f_Long ; echo -e "RFC 1912 CHECK" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
${PATH_nmap} -sn -Pn ${soa_host} --script dns-check-zone --script-args=dns-check-zone.domain=$s 2>/dev/null | grep '|' | tr -d '|_'  |
sed '/dns-check-zone:/d' | sed '/DNS check results/d' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/^ *//' | sed 's/^SOA$/* SOA/' |
sed 's/^NS$/* NS/' | sed 's/^MX$/* MX/' | tr '[:space:]' ' ' | sed 's/PASS/\nPASS/g' | sed 's/FAIL/\nFAIL/g' | sed 's/ERROR/\nERROR/g' |
sed 's/* SOA/\n* SOA\n/' | sed 's/* MX/\n* MX\n/' | sed 's/- Recursive queries//' | sed 's/* NS/\n* NS\n/' | sed 's/Server has/-/' |
sed 's/- SOA REFRESH/-/' | sed 's/- SOA RETRY/-/' | sed 's/- SOA EXPIRE/-/' | sed 's/All/- All/' | sed 's/ None/- None/' |
sed 's/DNS server response - //' | sed 's/was WITHIN/WITHIN/g' | sed 's/NOT/ - NOT -/g' | sed 's/entry check/entry check -/g' |
sed 's/Zone serial numbers/Serial numbers -/' | sed 's/DNS name server IPs/Name server IPs/' | sed 's/nameservers/name servers/g' |
sed '/^* /d' > $tempdir/check_zone ; echo -e "NS:\n" ; grep -E -i "name (server|servers)|queries" $tempdir/check_zone
echo -e "\nSOA:\n" ; grep -E "SOA|Serial" $tempdir/check_zone; echo -e "\nMX:\n" ; grep "MX" $tempdir/check_zone ; echo '' ; f_Long
}
f_AXFR(){
local s="$*" ; echo '' ; f_Long ; echo -e "[+] NS | ZONE TRANSFER | $s" ; f_Long
curl -s https://api.hackertarget.com/zonetransfer/?q=${s}${api_key_ht} > $tempdir/zone.txt
egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/zone.txt | sort -u -V >> $tempdir/ips.list
echo '' >> $tempdir/zone.txt ; cat $tempdir/zone.txt
}
f_RevDNS() {
local s="$*"
curl -s https://api.hackertarget.com/reversedns/?q=${s}${api_key_ht} | sed 's/no records found/no_records/' > $tempdir/out_revdns.txt
cat $tempdir/out_revdns.txt | sed 's/ / => /'  | awk '{print $1 "\t" $2 "\t" $3}' > $tempdir/revdns.txt; echo '' >> $tempdir/revdns.txt
if [[ $(wc -w $tempdir/revdns.txt  | cut -d ' ' -f 1 | tr -d ' ') -lt "2" ]] ; then
cat $tempdir/revdns.txt | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' ; else
echo '' ; cat $tempdir/revdns.txt ; fi
}
f_RevIP(){
local s="$*"
curl -s https://api.hackertarget.com/reverseiplookup/?q=${s}${api_key_ht} | sed 's/No DNS A records found/no_records/' > $tempdir/revip
if [[ $(wc -l $tempdir/revip | cut -d ' ' -f 1 | tr -d ' ') -lt "2" ]] ; then
cat $tempdir/revip.txt  | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' ; else
if [[ $(wc -l $tempdir/revip | cut -d ' ' -f 1 | tr -d ' ') -lt "1001" ]] ; then
dig +noall +answer +noclass +nottlid -f $tempdir/revip | sed 's/A/,/' | sed '/NS/d' | sed '/CNAME/d' | tr -d ' ' | sed 's/,/  /g' ; else
cat $tempdir/revip.txt ; echo '' ; fi ; fi
}
f_VHOSTS(){
local s="$*" ; echo '' ; f_Long ; echo -e "[+] ${s} | Virtual Hosts" ; f_Long ; echo ''
curl -s https://api.hackertarget.com/reverseiplookup/?q=${s}${api_key_ht} ; echo ''
}
f_certMAIL(){
${PATH_nmap} $x -Pn -sn --script hostmap-crtsh 2>/dev/null >> $tempdir/crt_raw
if ! [ "$x" = "$target_host_dom" ] ; then
${PATH_nmap} $target_host_dom -Pn -sn --script hostmap-crtsh 2>/dev/null >> $tempdir/crt_raw ; fi
grep '|' $tempdir/crt_raw | tr -d '|_' | sed '/hostmap-crtsh:/d' | sed '/subdomains:/d' | grep  '\\' | sed 's/\\n/\n/g' |
sed 's/^ *//' | sed 's/^*.//g' | sort -u > $tempdir/crt_results; cat $tempdir/crt_results >> $tempdir/hosts_raw
certmail=$(grep -s -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/crt_results | sort -u)
if [ -n "$certmail" ] ; then
echo ''; f_Long; echo -e "[+] CERTIFICATE E-MAIL ADDRESSES | SOURCE: crt.sh"; f_Long; echo -e "\n$certmail\n" ; fi
}
f_getSUBS(){
local s="$*"
curl -s https://api.hackertarget.com/hostsearch/?q=${s} | egrep -s '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' >> $tempdir/results_ht
egrep -s -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/results_ht | sort -uV >> $tempdir/ips.list
if ! [ $option_connect = "0" ] ; then
cut -d ',' -f 1 $tempdir/results_ht | sed 's/^ $//' | tr -d ' ' | sort -u >> $tempdir/hosts_ht
curl -s "https://api.sublist3r.com/search.php?domain=$s" > $tempdir/sublister.json
jq -r '.[]' $tempdir/sublister.json | sort -u >> $tempdir/hosts_raw ; fi
}
f_subs_HEADER(){
f_certMAIL "${x}"; f_getSUBS "${x}"
if ! [ "$x" = "$target_host_dom" ] ; then
f_getSUBS "${target_host_dom}"; fi
f_Long; echo "[+] NETWORKS & ORGANISATIONS (IPv4)"; f_Long; echo -e "\nSearching for hosts/subdomains...\n"
f_SUBS "${x}" ; echo -e "\nFound $(cat $tempdir/ips.list | sort -uV | wc -l) unique IPv4 hosts within the following resources:\n\n"
sort -t . -k 1,1n -k 2,2n -k 3,3n -u $tempdir/ips.list > $tempdir/ips_sorted.list
f_whoisTABLE "$tempdir/ips_sorted.list" ; f_Long
grep -w 'NA' $tempdir/whois_table.txt  | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sort -uV >> $tempdir/no_as.list
sort -t '|' -k 5 -u $tempdir/whois_table.txt | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' > $tempdir/net_lookup.list
cat $tempdir/whois_table.txt | sed '/ORG NAME/d' | grep -w -v 'NA' | sed '/^$/d' | sort -t . -k 1,1n -k 2,2n -u > $tempdir/table_sorted1
egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/table_sorted1 > $tempdir/prefix_lookup.list
cat $tempdir/whois_table.txt | sed '/ORG NAME/d' | grep -w -v 'NA' | sed '/^$/d' |
sort -t '|' -k 5 -u > $tempdir/table_sorted2; cat $tempdir/table_sorted2 >> $tempdir/table_sorted1
sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n -u $tempdir/table_sorted1 | awk -F '|' '{print $1,$3,$4,$5,$2}' OFS='|' > $tempdir/whois_table2_raw
cut -d '.' -f -2 $tempdir/whois_table2_raw  | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/$/.x.x/g' > $tempdir/whois_table2
grep 'ORG NAME' $tempdir/whois_table.txt | awk -F '|' '{print $1,$3,$4,$5,$2}' OFS='|' ; echo '' ; sed '/|/G' $tempdir/whois_table2
if [ -f $tempdir/no_as.list ] ; then
for n in $(cat $tempdir/no_as.list) ; do
f_BOGON "${n}"
if [ $bogon = "TRUE" ] ; then
echo $n >> $tempdir/bogons ; else
echo $n >> $tempdir/v4_no_as ; fi ; done
if [ -f $tempdir/bogons ] ; then
echo ''; f_Long; echo -e "IPv4 BOGONS\n___________\n\n"
for b in $(cat $tempdir/bogons | sort -uV); do
if [ -f $tempdir/subdomains ] ; then
bogon_sub=$(grep -w "${b}" $tempdir/subdomains)
elif [ -f $tempdir/subs_ht ] ; then
bogon_sub=$(grep -w "${b}" $tempdir/subs_ht) ; else
bogon_sub='' ; fi
if [ -n "$bogon_sub" ] ; then
echo "$bogon_sub" ; else
echo $b; fi; done ; echo '' ; fi ; fi
echo '' ; f_Long ; echo "[+]  PREFIXES & ROAs"
if [ -f $tempdir/v6_prefixes ] ; then
for p in $(cat $tempdir/v6_prefixes | sort -uV); do
f_PREFIX "${p}" ; done; fi
for i in $(cat $tempdir/prefix_lookup.list) ; do
curl -s "https://stat.ripe.net/data/network-info/data.json?resource=${i}" | jq -r '.data.prefix' >> $tempdir/prefixes.list ; done
for px in $(cat $tempdir/prefixes.list | sed '/null/d' | sed '/^$/d' | sort -t . -k 1,1n -k 2,2n -k 3,3n -u | sort -uV) ; do
f_PREFIX "${px}" ; done
if [ $option_whois = "y" ] ; then
for nip in $(cat $tempdir/net_lookup.list) ; do
f_domainNETS "${nip}" ; done ; fi
}
f_SUBS(){
local s="$*" ; cat $tempdir/hosts_raw | sort -u >> $tempdir/hosts
sort -t ',' -k 1 $tempdir/results_ht | sed 's/,/ => /' | awk '{print $3 "\t\t" $2 "\t" $1}' |
sort -t '>' -k 2 -V > $tempdir/subs_ht
echo '' > ${outdir}/Subdomains_HT.${s}.txt ; f_Long >> ${outdir}/Subdomains_HT.${s}.txt
echo "[+] Subdomains (IPv4) | SOURCE: hackertarget.com" >> ${outdir}/Subdomains_HT.${s}.txt
f_Long >> ${outdir}/Subdomains_HT.${s}.txt; echo '' >> ${outdir}/Subdomains_HT.${s}.txt
cat $tempdir/subs_ht >> ${outdir}/Subdomains_HT.${s}.txt
if ! [ $option_connect = "0" ] ; then
diff -N $tempdir/hosts_ht $tempdir/hosts | grep '>' | cut -d ' ' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | tr -d ' ' > $tempdir/resolve
dig @1.1.1.1 +noall +answer +nottlid +noclass -f $tempdir/hosts | sed '/CNAME/d' | sed '/NS/d' |
egrep -s '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' > $tempdir/hosts_res
resolve_count=$(cat $tempdir/resolve | wc -l)
if [[ $resolve_count -lt "1001" ]] ; then
sed 's/A/,/g' $tempdir/hosts_res | sed 's/^[ \t]*//;s/[ \t]*$//' | awk '{print $3, $2, $1}' | rev |
sed 's/^.//g' | rev | awk '{print $3, $2, $1}' | tr -d ' ' > $tempdir/subs2
cat $tempdir/results_ht | tr -d ' ' >> $tempdir/subs2
cat $tempdir/subs2 | sort -u |  sed 's/,/ => /' | awk '{print $3 "\t\t" $2 "\t" $1}' | sort -t '>' -k 2 > $tempdir/subdomains
awk '{print $NF}' $tempdir/subdomains | sort -u > $tempdir/hosts_ipv4
egrep -s -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/subdomains | sort -uV >> $tempdir/ips.list
echo '' > $tempdir/sub4; f_Long >> $tempdir/sub4; echo -e "[+] SUBDOMAINS (IPv4)" >> $tempdir/sub4
f_Long >> $tempdir/sub4; echo '' >> $tempdir/sub4 ; cat $tempdir/subdomains >> $tempdir/sub4
cat $tempdir/sub4 > ${outdir}/SUBDOMAINSall_v4.${s}.txt
if [ $option_subs = "2" ] ; then
dig @9.9.9.9 -t aaaa +noall +answer +nottlid +noclass -f $tempdir/hosts_ipv4 | grep 'AAAA' > $tempdir/hosts_ipv6.txt
echo '' > ${outdir}/SUBS.v6.$s.txt  ; f_Long >> ${outdir}/SUBS.v6.$s.txt
echo -e "[+] $x SUBDOMAINS (IPv6)" >> ${outdir}/SUBS.v6.$s.txt  ; f_Long >> ${outdir}/SUBS.v6.$s.txt
echo '' >> ${outdir}/SUBS.v6.$s.txt ; cat $tempdir/hosts_ipv6.txt | sed 's/AAAA/,/g' | sed 's/^[ \t]*//;s/[ \t]*$//' | tr -d ' ' |
sed 's/,/\t/g' >> ${outdir}/SUBS.v6.$s.txt ; fi ; fi ; fi
}
f_DELEGATION(){
local s="$*"; net_ip=$(echo $s | cut -d '/' -f 1)
if ! [ $rir = "lacnic" ] ; then
if [ $rir = "ripe" ] ; then
curl -s "https://stat.ripe.net/data/reverse-dns/data.json?resource=${s}" > $tempdir/revd.json
jq -r '.data.delegations[]' $tempdir/revd.json | grep -s -E -A 1 "domain|descr|nserver|admin-c|zone-c" | tr -d '\":,' |
sed 's/value//g' | sed 's/key//g' | sed 's/^ *//' | sed '/--/d' | sed '/^$/d' | tr '[:space:]' ' ' | sed 's/descr//g' |
sed 's/domain/\n/g' | sed 's/in-addr.arpa/in-addr.arpa\n/g' | sed 's/nserver/\n/g' | sed 's/admin-c/\nadmin-c/g' |
sed 's/zone-c / zone-c;/g' | sed 's/^ *//' | sed '/in-addr.arpa/{x;p;p;x;G}' | sed '/ip6.arpa/{x;p;p;x;G}' |
sed 's/admin-c /admin-c;/g'
jq -r '.data.delegations[]' $tempdir/revd.json | grep -s -A1 'nserver' | tr -d '\":,' |
grep -s 'value' | sed 's/value//' | sed 's/^ *//' >> $tempdir/authns ; echo '' ; else
if [[ ${net_ip} =~ $REGEX_IP4 ]] ; then
reverse=$(echo $net_ip | awk -F'.' '{printf $4 "." $3 "." $2}')
if [ $rir = "arin" ] ; then
whois -h whois.arin.net d $reverse.in-addr.arpa. > $tempdir/revd.txt ; else
whois -h whois.$rir.net -- "--no-personal $reverse.in-addr.arpa." > $tempdir/revd.txt ; fi
if [[ $(grep -s -c -E "NameServer|nserver:" $tempdir/whois) -lt 1 ]]; then
if [ $rir = "arin" ] ; then
whois -h whois.arin.net d $reverse.in-addr.arpa. > $tempdir/revd_arin ; else
whois -h whois.$rir.net -- "--no-personal $reverse.in-addr.arpa." > $tempdir/revd.txt ; fi ; fi
if [[ $(grep -s -c -E "NameServer|nserver:" $tempdir/whois) -gt 0 ]]; then
grep -E "^domain:|^descr:|^admin-c:|^zone-c:|^org:|^nserver:|^Name:|NameServer:" $tempdir/revd.txt | sed '/Name:/{x;p;x;G}' |
sed '/domain:/{x;p;x;G}' | cut -d ' ' -f 2- | sed 's/^ *//'
grep -E "^NameServer:|^nserver:" $tempdir/revd.txt | awk '{print $NF}' | sed 's/^ *//' | tr -d ' ' >> $tempdir/auth_ns; else
echo -e "No reverse DNS delegation found for $reverse.in-addr.arpa."; fi ; fi ; fi ; fi
}

#********************** NETWORK ENUMERATION - DNS  ***********************
f_nmapSL() {
local s="$*" ; echo '' ; ${PATH_nmap} ${s} -sn -Pn -sL ${dns_servers} 2>/dev/null > $tempdir/nmrdns
grep ')' $tempdir/nmrdns | sed '/Starting Nmap/d' | sed '/Nmap done/d' | sed 's/(/=> /g' | awk '{print $7 "\t\t" $6 "\t" $5}' | tr -d ')'
}
f_NETrDNS() {
if ! [ $option_netdetails3 = "0" ] ; then
f_Long; echo -e "REVERSE DNS\n\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' ; else
echo -e "\n* Reverse DNS\n" ; fi
if [ $option_source = "3" ] || [ $option_connect = "0" ] ; then
f_RevDNS "${s}" | tee $tempdir/ipv4_hosts.txt ; else
f_nmapSL "${s}" | tee $tempdir/ipv4_hosts.txt ; fi
if grep -q -E "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" $tempdir/ipv4_hosts.txt; then
cat $tempdir/ipv4_hosts.txt
if [ $option_ip6 = "y" ] ; then
awk '{print $3}' $tempdir/ipv4_hosts.txt | sed 's/^[ \t]*//;s/[ \t]*$//' > $tempdir/hosts.txt
echo ''; f_Long ; echo -e "\n* IPv6 Hosts\n"
dig aaaa +noall +answer +noclass +nottlid -f $tempdir/hosts.txt | sed 's/AAAA/,/' | sed '/NS/d' |
sed '/CNAME/d' | tr -d ' '  > $tempdir/ipv6_hosts.txt
sort -t ',' -k 2 -uV $tempdir/ipv6_hosts.txt | sed 's/,/,  /g' > $tempdir/rev6.txt
cat $tempdir/rev6.txt ; fi ; else
echo -e "No results\n" ; fi
}
f_OPTIONSnetRDNS(){
echo -e "\n${B}Nameservers (System Defaults)${D}\n" ; f_systemDNS
echo -e "\n${B}Options  >  ${G2}Reverse DNS${B}  >  Sources >\n"
echo -e "${B} [1] ${G2}NMAP${B} >${D}  default NS  (no max. size)"
echo -e "${B} [2] ${G2}NMAP${B} >${D}  custom NS  (no max. size)"
echo -e "${B} [3] ${G2}API${B}  >${D}  hackertarget.com IP API (max. size: /24)"
}
f_rdnsCONS(){
local s="$*" ; net_ip=$(echo "$s" | cut -d '/' -f 1)
curl -s "https://stat.ripe.net/data/reverse-dns-consistency/data.json?resource=${s}" > $tempdir/dnscons.json
if [[ ${net_ip} =~ $REGEX_IP4 ]] ; then
jq -r '.data.prefixes.ipv4' $tempdir/dnscons.json > $tempdir/dnscons ; else
jq -r '.data.prefixes.ipv6' $tempdir/dnscons.json > $tempdir/dnscons ; fi
cat $tempdir/dnscons | tr -d '][}{,"' | sed 's/^ *//' | sed '/^$/d' | tr '[:space:]' ' ' | sed 's/domains:/DOMAINS:\n\n/' |
sed 's/domain: /\n/g' | sed 's/prefix:/ - /g' | sed 's/found:/ > /g' | sed 's/true/true\n/g' | sed 's/false/false\n/g' |
sed 's/complete:/\n\n\ncomplete:/g' | sed '/complete:/a \____________________\n'
}

#********************** NETWORK ENUMERATION - WHOIS  ***********************
f_whoisNET(){
local s="$*" ; query="$s"; export query ; net_ip=$(echo $s | cut -d '/' -f 1) ; echo '' ; f_getRIR "${s}"
if [ $rir = "lacnic" ] ; then
whois -h whois.lacnic.net $s > $tempdir/whois
elif [ $rir = "arin" ]; then
f_arin_WHOIS "${s}"; else
whois -h whois.${rir}.net -- "--no-personal -x $s" > $tempdir/whois
if [[ $(grep -s -w -c '^netname:' $tempdir/whois ) = 0 ]] ; then
whois -h whois.${rir}.net -- "--no-personal $s" > $tempdir/whois; fi; fi
if [ $rir = "lacnic" ] ; then
f_Long ; echo "NET | $s" ; f_Long; f_lacnicWHOIS "${s}"; else
netabuse=$(grep -E -a -s -m 1 "^OrgAbuseEmail:|^% Abuse|^abuse-mailbox:|^e-mail:|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/whois |
grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b")
if [ -z "$netabuse" ] ; then
netabuse=$(grep -E -o -m 2 "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/whois); fi
net_name=$(grep -E -i -m 1 "^netname:|^na:|^net-name:" $tempdir/whois | cut -d ':' -f 2- | sed 's/^ *//')
if [ -n "$net_name" ] ; then
f_Long ; echo "NET |  $net_name  |  Query:  $s" ; f_Long; else
f_Long ; echo "NET | $s" ; f_Long; fi
echo "[@]: $netabuse" | tr '[:space:]' ' ' ; echo -e "\n____\n"; f_netSUM "${s}"; fi
}
f_ipCALC(){
local s="$*"
cidrs=$(${PATH_ipcalc} -r $s | sed '/deaggregate/d')
if [[ $(echo "$cidrs" | wc -w) = 1 ]] && [ "$cidrs" = "$net_resource" ] ; then
${PATH_ipcalc} -b -n ${cidrs} > $tempdir/ipcal; hosts=$(grep 'Hosts/Net' $tempdir/ipcal | awk '{print $2}')
echo -e "             $(grep 'Netmask' $tempdir/ipcal | awk '{print $2}'), $(grep 'Wildcard:' $tempdir/ipcal | awk '{print $NF}')  $hosts hosts\n"; else
for i in $cidrs ; do
${PATH_ipcalc} -b -n ${i} > $tempdir/ipcal
hosts=$(grep 'Hosts/Net' $tempdir/ipcal | awk '{print $2}')
mask=$(grep 'Netmask' $tempdir/ipcal | awk '{print $2}')
if [ -n "$hosts" ] ; then
echo -e "             $i  ($mask,  $hosts hosts)\n"; rm $tempdir/ipcal; fi ; done; fi
}
f_netSUM(){
local s="$*" ; net_ip=$(echo $s | cut -d '/' -f 1); trimmed=$(echo $s | tr -d ' ')
net_range=$(grep -E -i -m 1 "^inetnum|^inet6num:|^netrange:|^net-range|^in:|^i6:" $tempdir/whois | cut -d ' ' -f 2- | sed 's/^ *//')
range_trimmed=$(echo $net_range | tr -d ' ')
net_name=$(grep -E -i -m 1 "^netname:|^na:|^net-name:" $tempdir/whois | cut -d ':' -f 2- | sed 's/^ *//'); export net_name
ctry=$(grep -E -i -m 1 "^country:|^cy:" $tempdir/whois | cut -d ':' -f 2- | sed 's/^ *//')
created=$(grep -E -i -m 1 "^cr:|^created:|^RegDate:" $tempdir/whois | grep -E -o "[0-9]{4}-[0-9]{2}-[0-9]{2}")
rir_caps=$(echo $rir | tr [:lower:] [:upper:])
descr=$(grep -E -m 1 "^descr:" $tempdir/whois | cut -d ':' -f 2- | sed 's/^ *//' | tr '[:space:]' ' ' ; echo '')
org_whois=$(grep -E -i -m 1 "^organization:|^org-name:|^owner:|^og:|^oa:" $tempdir/whois | cut -d ':' -f 2- | sed 's/^ *//')
net_status=$(grep -E -i -m 1 "^status:|^NetType:" $tempdir/whois | cut -d ':' -f 2- | sed 's/^ *//')
cidr=$(grep -E -m 1 "^CIDR:" $tempdir/whois | cut -d ':' -f 2- | sed 's/^ *//')
if ! [[ ${net_ip} =~ $REGEX_IP4 ]] ; then
if [ $rir = "arin" ] ; then
target=$(echo "$cidr" | head -1) ; geo_target="$target"; else
net_resource="$net_range"; target="$net_range"; geo_target="$target"; fi
curl -s "https://stat.ripe.net/data/prefix-overview/data.json?resource=${target}" > $tempdir/pov.json; else
curl -s "https://stat.ripe.net/data/prefix-overview/data.json?resource=${range_trimmed}" > $tempdir/pov.json
converted=$(jq -r '.messages[]' $tempdir/pov.json | grep 'range' | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}')
if [ -n "$converted" ] ; then
geo_target="$converted"; net_resource="$converted"; else
geo_target=$(echo $s | cut -d '-' -f 1 | tr -d ' '); net_resource=''; fi
if [ $target_type = "net" ] && ! [ "$converted" = "$s" ] ; then
curl -s "https://stat.ripe.net/data/prefix-overview/data.json?resource=${s}" > $tempdir/pov2.json ; fi; fi
resource=$(jq -r '.data.resource' $tempdir/pov.json); num_related=$(jq -r '.data.actual_num_related' $tempdir/pov.json)
announced=$(jq -r '.data.announced' $tempdir/pov.json); lp=$(jq -r '.data.is_less_specific' $tempdir/pov.json)
if [ $announced = "true" ] ; then
as=$(jq -r '.data.asns[0].asn' $tempdir/pov.json); export as; is_lp="| less specific: $lp" ; else
is_lp=''; fi
curl -s "https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource=${geo_target}" > $tempdir/netgeo.json
netgeo=$(jq -r '.data.located_resources[].locations[] | .country' $tempdir/netgeo.json | sort -u | tr '[:space:]' ' ' ; echo '')
if [ -n "$net_resource" ] ; then
if [ -n "$net_status" ] ; then
echo -e "\nNet:         $net_name  | $net_resource | $rir_caps"
echo -e "\n             $net_status | $created\n" ; else
echo -e "\nNet:         $net_name  | $n_resource | $created | $rir_caps" ; fi ; else
if [ -n "$net_status" ] ; then
echo -e "\nNet:         $net_name  | $created | $net_status | $rir_caps"; else
echo -e "\nNet:         $net_name  | $net_resource | $created | $rir_caps" ; fi ; fi
if ! [[ ${net_ip} =~ $REGEX_IP4 ]] && [ $rir = "arin" ] ; then
echo -e "\nRange:       $net_range\n" ; fi
if [[ ${net_ip} =~ $REGEX_IP4 ]] ; then
echo -e "\nRange:       $net_range\n"; f_ipCALC "${range_trimmed}"; fi
if [ -n "$cidr" ] && ! [ $cidr = "$net_resource" ] ; then
echo -e "CIDR:        $cidr\n" ; fi
if [[ $(echo "$netgeo" | wc -w ) -lt 22 ]]; then
echo -e "\nGeo:         $ctry (whois), $netgeo (maxmind)"; fi
if [ -n "$descr" ] ; then
echo -e "\nDescr:       $descr" ; fi
if [ -f $tempdir/pov2.json ]; then
echo ''; fi
echo -e "\nPrefix:      $resource | announced: $announced | related prefixes: $num_related $is_lp"
if [ -f $tempdir/pov2.json ]; then
resource_query=$(jq -r '.data.resource' $tempdir/pov2.json)
if ! [ "$resource" = "$resource_query" ] ; then 
lp_qu=$(jq -r '.data.is_less_specific' $tempdir/pov2.json); announced_query=$(jq -r '.data.announced' $tempdir/pov2.json)
if [ $announced_query = "true" ] ; then
is_lp_query="| less specific: $lp_qu" ; else
is_lp_query=''; fi
echo -e "\n             $resource_query | announced: $announced_query $is_lp_query"; fi ; fi 
if [[ $(echo "$netgeo" | wc -w ) -gt 21 ]]; then
echo ''; f_Long ; echo "LOCATION" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
echo -e "Country (whois):\n"; echo -e "$ctry"; echo -e "\nGeolocation (maxmind):\n"; echo "$netgeo" | fmt -w 60; fi
if [ $option_detail = "2" ] ; then
f_getORGNAME "$tempdir/whois"; fi
if [ $target_type = "net" ] ; then
query="$s"; export query
if [ $rir = "arin" ]; then
f_ORG "$tempdir/whois" ; else
if [ $option_detail = "1" ] || [ $option_detail = "3" ]; then
echo '' ; f_ORG "$tempdir/whois"
ac=$(grep -E "^admin-c:" $tempdir/whois | cut -d ':' -f 2- | sed 's/^ *//' | head -1); f_Long; f_ADMIN_C "${ac}" ; else
f_getWHOIS "${s}" ; f_POC "$tempdir/whois.txt" ; fi; fi
if [ -n "$announced_query" ] ; then
if [ $announced = "true" ] && [ $announced_query = "true" ] ; then
f_PREFIX "$(jq -r '.data.resource' $tempdir/pov2.json)"; fi ; fi
f_PREFIX "$(jq -r '.data.resource' $tempdir/pov.json)"
if [ -f $tempdir/pov2.json ] ; then
rm $tempdir/pov2.json; fi
if [ $option_detail = "2" ] || [ $option_detail = "3" ]; then
f_netDETAILS "${s}"; fi; else
f_NETGEO "${s}" > $tempdir/network_maxmind.txt; fi
}
f_netDETAILS(){
local s="$*" ; net_ip=$(echo $s | cut -d '/' -f 1)
if [ $option_netdetails1 = "2" ] || [ $option_netdetails1 = "3" ]; then
f_RELATED "${s}" ; echo '' ; f_ROUTE_CONS "${s}" ; f_Long; f_NETGEO "${s}" ; fi
if ! [ $option_netdetails1 = "0" ] && ! [ $rir = "lacnic" ]; then
if [[ $(grep -s -w -c '^netname:' $tempdir/whois ) -gt "0" ]] ; then
net_name=$(grep -E -i -m 1 "^netname:|^na:|^net-name:" $tempdir/whois | cut -d ':' -f 2- | sed 's/^ *//')
elif [[ $(grep -s -w -c '^netname:' $tempdir/whois.txt ) -gt "0" ]] ; then
net_name=$(grep -E -i -m 1 "^netname:|^na:|^net-name:" $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//') ; else
net_name=$(whois -h whois.pwhois.org "$s" | grep -E "^Net-Name:" | cut -d ':' -f 2- | sed 's/^ *//'); fi
f_netRESOURCES "${net_name}" ; fi
if [ $option_netdetails2 = "1" ] || [ $option_netdetails2 = "3" ]; then
if ! [ $rir = "lacnic" ] ; then
f_SUBNETS "${s}" ; fi ; fi
if ! [ $option_netdetails3 = "0" ] ; then
f_Long; echo "REVERSE DNS" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
if  [ $option_netdetails3 = "1" ] || [ $option_netdetails3 = "2" ] ; then
f_nmapSL "${s}"; fi
if  [ $option_netdetails3 = "3" ] ; then
f_RevDNS "${s}" ; fi ; fi
if [ $option_netdetails4 = "1" ] ; then
echo ''; f_Long; echo "BANNERS" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
f_BANNERS "${s}" ; fi
if [ $option_netdetails2 = "2" ] || [ $option_netdetails2 = "3" ]; then
if [ $rir = "ripe" ] ; then
f_Long ; echo "WHOIS-REV.DNS CONSISTENCY" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
f_rdnsCONS "${s}" > $tempdir/dns_cons
complete=$(grep 'complete:' $tempdir/dns_cons | grep 'true' | sed '/complete:/G')
if [ -n "$complete" ] ; then
echo -e "$complete" ; else
grep 'complete:' $tempdir/dns_cons | sed '/complete:/{x;p;x;G}'
incomplete=$(grep -v 'complete:' $tempdir/dns_cons | grep 'false')
if [ -n "$incomplete" ] ; then
echo -e "WHOIS entries missing for zones:\n"
echo "$incomplete" | awk -F'>' '{print $1}' ; echo '' ; fi ; fi
echo ''; f_Long; echo "REV. DNS LOOKUP ZONES" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
f_DELEGATION "${s}" ; else
echo -e "Option not available for non-RIPE-managed address space\n" ; fi ; fi
}
f_NET_HEADER(){
local s="$*" ; net_ip=$(echo $s | cut -d '/' -f 1)
asn=$(curl -s "https://stat.ripe.net/data/network-info/data.json?resource=${s}" | jq -r '.data.asns[0]')
if [[ ${net_ip} =~ $REGEX_IP4 ]] ; then
reg=$(curl -s "https://stat.ripe.net/data/rir/data.json?resource=${s}" | jq -r '.data.rirs[0].rir' | cut -d ' ' -f 1 | tr -d ' ' |
tr [:upper:] [:lower:]) ; else
curl -s "https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=${s}" > $tempdir/ac.json
reg=$(jq -r '.data.authoritative_rir' $tempdir/ac.json); fi
if [ $reg = "arin" ] ; then
whois -h whois.arin.net $s > $tempdir/whois.txt
range=$(grep -a -E "^CIDR:" $tempdir/whois.txt | cut -d ' ' -f 2- | sed 's/^ *//' | head -3 | tr '[:space:]' ' '; echo '')
elif [ $reg = "lacnic" ] ; then
whois -h whois.lacnic.net $s > $tempdir/whois.txt ; else
whois -h whois.$reg.net -- "-r -F $s" | tr -d '*' | sed 's/^ *//' > $tempdir/whois.txt ; fi
netn=`grep -s -a -i -E -m 1 "^netname:|^na:" $tempdir/whois.txt | cut -d ' ' -f 2- | sed 's/^ *//'`
range=`grep -s -a -i -E -m 1 "^netrange:|^in:" $tempdir/whois.txt | cut -d ' ' -f 2- | tr -d ' ' | sed 's/^ *//'`
whois_cc=`grep -E -i -a -m 1 "^country:|^cy:" $tempdir/whois.txt | cut -d ' ' -f 2- | sed 's/^ *//'`
hostnum=$(ipcalc -b -n ${x} | grep -s -E "^Hosts/Net" | cut -d ':' -f 2 | sed 's/Class.*//' | tr -d ' ')
if [ $reg = "lacnic" ] ; then
netabu=$(grep -E -o -m 2 "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/whois.txt | sort -u -V | tr '[:space:]' ' ' ; echo '') ; else
netabu=$(grep -E -i -m 1 "^OrgAbuseEmail:|^% Abuse|^abuse-mailbox:|^e-mail:" $tempdir/whois.txt |
grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b") ; fi
echo ''; f_Long; echo -e "$x, $hostnum hosts | $whois_cc | AS $asn | $(date)"; f_Long
echo -e "[@]: $netabu | $netn - $range" ; echo -e "____\n"
}
f_POC(){
local s="$*"
if [ $domain_enum = "false" ] ; then
f_Long; echo "CONTACT" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' ; else
f_Shorter; grep -s -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" ${s} | sort -u; f_Shorter; fi
if [ $rir = "arin" ] ; then
f_ARIN_ORG "$s"
elif [ $rir = "lacnic" ] ; then
f_ORG "$s" ; else
if [[ $(grep -s -w -c '^org-name:' $s ) -gt "0" ]] ; then
echo '' ; sed -e '/./{H;$!d;}' -e 'x;/organisation:/!d' $s |
sed -n '/organisation:/,/organisation:/p' | grep -E -a -s "^org-name:|^address:|^phone:|^e-mail:" |
sed '/org-name:/a nnn' | sed '/phone:/i nnn' | sed '/e-mail:/i nnn' | cut -d ':' -f 2- | sed 's/^ *//' | tr '[:space:]' ' ' |
sed 's/nnn /\n/g' ; echo '' ; fi
if [[ $(grep -s -w -c '^role:' $s ) -gt "0" ]] ; then
sed -e '/./{H;$!d;}' -e 'x;/role:/!d' $s | grep -E -a "^role:|^address:|^phone:|^nic-hdl:" |
sed '/role:/a nnn' | sed '/role:/i nnn' | sed '/phone:/i nnn' | sed '/e-mail:/i nnn' | sed '/nic-hdl:/i nnn' |
sed '/nic-hdl:/a nnn' | cut -d ':' -f 2- | sed 's/^ *//' | tr '[:space:]' ' ' | sed 's/nnn /\n/g'
if [[ $(grep -s -w -c '^person:' $s ) -gt "0" ]] ; then
echo '' ; fi ; fi
if [[ $(grep -s -w -c '^person:' $s ) -gt "0" ]] ; then
sed -e '/./{H;$!d;}' -e 'x;/person:/!d' $s | grep -E -a "^person:|^address:|^phone:|^e-mail:|^nic-hdl:" |
sed '/person:/a nnn' | sed '/person:/i nnn' | sed '/phone:/i nnn' | sed '/e-mail:/i nnn' | sed '/nic-hdl:/i nnn' |
sed '/nic-hdl:/a nnn' | cut -d ':' -f 2- | sed 's/^ *//' | tr '[:space:]' ' ' | sed 's/nnn /\n/g' ; echo ''
sed -e '/./{H;$!d;}' -e 'x;/person:/!d' $s | grep -a -s "^nic-hdl" | sed '/^$/d' |
cut -d ':' -f 2- | sed 's/^ *//' >> $tempdir/nic_hdls ; fi
orgs=$(grep -E "^organisation|^abuse-c" $s | sed 's/organisation:/org:/' | tr ':' ';' | tr -d ' ' |
sort -u -V | tr '[:space:]' ' ' | fmt -s -w 50 ; echo '')
admin_c=$(grep -E "^admin-c:|tech-c:" $s  | tr ':' ';' | tr -d ' ' | sort -u -V | tr '[:space:]' ' ' |
fmt -s -w 50 ; echo '')
mntners=$(grep -E "^mnt-by:|^mnt-lower:|^mnt-ref:" $s | sed '/RIPE-NCC-*/d' | tr ':' ';' | tr -d ' ' | sort -u -V |
tr '[:space:]' ' ' | fmt -s -w 50 ; echo ''); f_Shorter
if [ $domain_enum = "false" ] ; then
grep -s -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $s | sort -u | tr '[:space:]' ' ' | fmt -s -w 50; f_Shorter ; fi
if [ -n "$orgs" ] ; then
echo "$orgs" ; fi
if [ -n "$admin_c" ] ; then
echo "$admin_c" ; fi
if [ -n "$mntners" ] ; then
echo "$mntners" ; fi; fi
}
f_netRESOURCES(){
local s="$*" ; echo '' ; f_Long
echo "RESOURCES FOR '$s' ($rir)" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
if [ $rir = "arin" ] ; then
whois -h whois.arin.net -- "n . + > $s" | sed '/#/d' | sed '/^$/d' > $tempdir/netwho_raw
netcount=$(grep -E "^NetRange:" $tempdir/netwho_raw | wc -l); echo -e "Networks: $netcount\n"
grep -E "^NetRange:|^CIDR:|^NetHandle:|^Organization:|^City:|^Country:|^OrgAbuseEmail:" $tempdir/netwho_raw |
sed 's/NetRange:       /NetRange /g' | sed 's/CIDR:           /CIDR /g' | sed 's/NetHandle:      /Handle /g' | sed 's/Organization:   /Org /g' |
sed 's/City:           /City /g' | sed 's/Country:        /Ctry /g' | tr '[:space:]' ' ' | sed 's/NetRange /\n\n\n/g' | sed 's/CIDR/|/g' |
sed 's/Handle/|/g' | sed 's/City/|/g' | sed 's/Ctry/|/g' | sed 's/OrgAbuseEmail:  /AM /g' | sed 's/AM/|/g' | sed 's/Org / \n\n/g' > $tempdir/netwho
if [[ $netcount -lt "26" ]] ; then
cat $tempdir/netwho ; else
echo -e "Output has been written to file."
echo '' > $outdir/NetRanges.$s.txt; f_Long >> $outdir/NetRanges.$s.txt
echo "RESOURCES FOR '$s' ($rir)" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' >> $outdir/NetRanges.$s.txt
cat $tempdir/netwho >> $outdir/NetRanges.$s.txt ; fi ; fi
if ! [ $rir = "lacnic" ] && ! [ $rir = "arin" ] ; then
if [ -f $tempdir/whois.txt ] ; then
cat $tempdir/whois.txt > $tempdir/contact_handles; else
cat $tempdir/whois > $tempdir/contact_handles; fi
whois -h whois.$rir.net -- "-F $s" | tr -d '*' | sed 's/^ *//' > $tempdir/netwho_raw
if [[ $(grep -s -E -c "^in:" $tempdir/netwho_raw) -gt "0" ]] ; then
sed -e '/./{H;$!d;}' -e 'x;/in:/!d' $tempdir/netwho_raw | grep -E "^in:|^cy:|^ac:" | sed '/in:/{x;p;x;}' > $tempdir/netwho4_raw
cat $tempdir/netwho4_raw | sed 's/cy:/ |/g' | sed 's/ac: / | admin-c;/g' | tr '[:space:]' ' ' | sed 's/in:/\n/g' |
sed 's/^ *//' | cut -d '|' -f -3 | sed '/|/G' > $tempdir/netwho ; fi
if [[ $(grep -s -E -c "^i6:" $tempdir/netwho_raw) -gt "0" ]] ; then
sed -e '/./{H;$!d;}' -e 'x;/i6:/!d' $tempdir/netwho_raw | grep -E "^i6:|^cy:|^ac:" | sed '/i6:/{x;p;x;}' > $tempdir/netwho6_raw
cat $tempdir/netwho6_raw | sed 's/cy:/ |/g' | sed 's/ac: / | admin-c;/g' | tr '[:space:]' ' ' | sed 's/i6:/\n/g' |
sed 's/^ *//' | cut -d '|' -f -3 > $tempdir/netwho6 ; fi
sed -e '/./{H;$!d;}' -e 'x;/person:/!d' $tempdir/contact_handles | grep -a -s "^nic-hdl" | sed '/^$/d' | cut -d ':' -f 2- |
sed 's/^ *//' >> $tempdir/nic_hdls
sed -e '/./{H;$!d;}' -e 'x;/role:/!d' $tempdir/contact_handles | grep -a -s "^nic-hdl" | sed '/^$/d' | cut -d ':' -f 2- |
sed 's/^ *//' >> $tempdir/nic_hdls
sort -u -V $tempdir/nic_hdls > $tempdir/nh_list1
cat $tempdir/netwho | cut -d '|' -f 3 | cut -s -d ';' -f 2 | sed 's/^ *//' | sed '/^$/d' | tr -d ' ' | sort -u -V > $tempdir/nh_list2
admins_other=$(diff $tempdir/nh_list1 $tempdir/nh_list2 | grep '>' | cut -d ' ' -f 2 | head -12)
nets=$(cat $tempdir/netwho_raw | grep "^in:" | cut -d ':' -f 2- | sed 's/^ *//' | egrep '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | tr -d ' ')
netcount=$(echo "$nets" | wc -w)
v6nets=$(cat $tempdir/netwho_raw | grep -E "^i6:" | cut -d ' ' -f 2- | sed 's/^ *//'); netcount6=$(echo "$v6nets" | wc -w)
if [[ $netcount6 -gt "25" ]] || [[ $netcount -gt "25" ]] ; then
echo '' > $outdir/NetRanges.$s.txt; f_Long >> $outdir/NetRanges.$s.txt
echo "RESOURCES FOR '$s' ($rir)" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' >> $outdir/NetRanges.$s.txt; fi
echo -e "Networks:\n"
if [ -n "$v6nets" ] ; then
echo -e "IPv6: $netcount6" ; fi
if [ -n "$nets" ] ; then
echo -e "IPv4: $netcount"
if [[ $netcount -gt "1" ]] || [ -n "$v6nets" ] ; then
echo '' ; fi ; fi
if [ -n "$v6nets" ] ; then
if [[ $netcount6 -lt "26" ]] ; then
cat $tempdir/netwho6 | sed '/|/G' ; else
echo -e "IPv6 Resources: Output has been written to file.\n" ; cat $tempdir/netwho6 >> $outdir/NetRanges6.$s.txt ; fi ; fi
if [ -n "$nets" ] ; then
cat $tempdir/netwho > $tempdir/resources_v4
if [[ $netcount -gt "1" ]] ; then
f_Shorter >> $tempdir/resources_v4  ; fi
for n in $(cat $tempdir/netwho_raw | grep "^in:" | cut -d ':' -f 2- | sed 's/^ *//' | egrep '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | tr -d ' ');do
${PATH_ipcalc} "${n}" | sed '/deaggregate/d' | sed '/^$/d'; done > $tempdir/ranges
cat $tempdir/ranges | tr '[:space:]' ' ' | fmt -s -w 40 >> $tempdir/resources_v4
echo '' >> $tempdir/resources_v4
if [[ $netcount -lt "26" ]] ; then
cat $tempdir/resources_v4 ; else
echo -e "\nIPv4 Resources: Output has been written to file" ; cat $tempdir/resources_v4 >> $outdir/NetRanges.$s.txt ; fi ; fi
if [ -n "$admins_other" ] ; then
f_Long; echo -e "CONTACTS" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
for i in $admins_other ; do
whois -h whois.$rir.net -- "-r -F $i" | tr -d '*' | sed 's/^ *//' > $tempdir/acwhois
sed -e '/./{H;$!d;}' -e 'x;/pn:/!d' $tempdir/acwhois | grep -E -a -s "^pn:|^ad:|^cy:|^ph:|^mb:|^nh:" |
sed '/pn:/{x;p;x;}' | cut -d ':' -f 2- | sed 's/^ *//'
sed -e '/./{H;$!d;}' -e 'x;/ro:/!d' $tempdir/acwhois | grep -E -a -s "^ro:|^ad:|^cy:|^ph:|^mb:|^nh:" |
sed '/ro:/{x;p;x;}' | cut -d ':' -f 2- | sed 's/^ *//' ; done ; fi ; fi
}
f_domainNETS(){
local s="$*" ; net_ip=$(echo $s | cut -d '/' -f 1) ; echo '' >> $tempdir/domain_nets ; f_getRIR "${s}"
if [ $rir = "arin" ] || [ $rir = "lacnic" ] ; then
whois -h whois.$rir.net ${s} > $tempdir/whois.txt ; else
whois -h whois.$rir.net -- "-B ${s}" > $tempdir/whois.txt ; fi
netname=$(grep -s -i -E -m 1 "^netname:|^net-name:|^inetrev:" $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//')
curl -s "https://stat.ripe.net/data/network-info/data.json?resource=${s}" > $tempdir/net.json
asn=$(jq -r '.data.asns[0]' $tempdir/net.json); pfx=$(jq -r '.data.prefix' $tempdir/net.json)
if [ -n "$netname" ] ; then
ctry=$(grep -E -i -m 1 "^country:" $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//')
netrange=$(grep -i -E -m 1 "^netrange:|^inetnum:|^inet6num:" $tempdir/whois.txt | cut -d ' ' -f 2- | sed 's/^ *//')
range_trimmed=$(echo $netrange | tr -d ' '); rir_caps=$(echo $rir | tr [:lower:] [:upper:])
created=$(grep -E -i -m 1 "^created:|^RegDate:" $tempdir/whois.txt | grep -E -o "[0-9]{4}-[0-9]{2}-[0-9]{2}")
descr=$(grep -E -m 1 "^descr:" $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//' | tr '[:space:]' ' ' ; echo '')
allocation_status=$(grep -E -i -m 1 "^status:|^NetType:" $tempdir/whois.txt | cut -d ':' -f 2- | sed 's/^ *//')
f_Long >> $tempdir/domain_nets
echo -e "[+]  $netname" >> $tempdir/domain_nets ; f_Long >> $tempdir/domain_nets
echo -e "\nQueried Resource:  $netrange" >> $tempdir/domain_nets
echo -e "_________________\n" >> $tempdir/domain_nets
if [ -n "$descr" ] ; then
echo -e "\n$descr" >> $tempdir/domain_nets; fi
if [ $rir = "lacnic" ] || [ -z "$allocation_status" ] ; then
echo -e "\n$created | $ctry | $rir_caps | $pfx  (AS $asn)\n" >> $tempdir/domain_nets; else
echo -e "\n$created | $ctry | $rir_caps | $allocation_status | $pfx | AS $asn\n" >> $tempdir/domain_nets ; fi
f_POC "$tempdir/whois.txt" >> $tempdir/domain_nets ; f_netRESOURCES "${netname}" >> $tempdir/domain_nets ; fi
}
f_RELATED(){
local s="$*"; net_ip=$(echo $s | cut -d '/' -f 1); curl -s "https://stat.ripe.net/data/related-prefixes/data.json?resource=${s}" > $tempdir/rel.json
related=$(jq -r '.data.prefixes[] | {A: .origin_asn, N: .asn_name, P: .prefix, R: .relationship}' $tempdir/rel.json | tr -d '{",}' |
sed 's/^ *//' | sed '/^$/d' | tr '[:space:]' ' ' | sed 's/A: /\n\nAS/g' | sed 's/N:/-/g' | sed 's/R:/|/g' | sed 's/P:/|/g')
if [ -n "$related" ] ; then
f_Long; echo "RELATED NETWORKS" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
less_sp=$(echo "$related" | grep -w 'Overlap - Less Specific'); more_sp=$(echo "$related" | grep -w 'Overlap - More Specific')
adjacent=$(jq -r '.data.prefixes[] | {P: .prefix, AS: .origin_asn, N: .asn_name, R: .relationship}' $tempdir/rel.json  | tr -d '{,"}' |
sed 's/^ *//' | sed '/^$/d' | tr '[:space:]' ' ' | sed 's/P: /\n/g' | sed 's/AS:/| AS/g' | sed 's/N:/-/g' | sed 's/R:/|/g')
adj_left=$(echo "$adjacent" | grep -w 'Adjacency - Left'); adj_right=$(echo "$adjacent" | grep -w 'Adjacency - Right')
rel_asn=$(jq -r '.data.prefixes[].origin_asn' $tempdir/rel.json | sort -ug)
if [ -n "$less_sp" ] || [ -n "$more_sp" ] ; then
specifics="true" ; else
specifics="false" ; fi
if [ -n "$adj_left" ] ; then
echo -e "\nAdjacent Left\n_____________\n" ; echo "$adj_left" | sed '/|/G' | cut -d '|' -f -2 | sed 's/| AS:/- AS/g'; fi
if [ -n "$adj_right" ] ; then
echo -e "\nAdjacent Right\n______________\n"; echo "$adj_right" | sed '/|/G' | cut -d '|' -f -2 | sed '/|/G' | sed 's/| AS:/- AS/g'; else
if [ -n "$less_sp" ] || [ -n "$more_sp" ] ; then
echo '' ; fi ; fi
if [ -n "$less_sp" ] ; then
echo -e "Less Specific\n_____________\n"
for r_as in $rel_asn ; do
lp_sorted=$(echo "$less_sp" | grep -w -E "AS${r_as}")
if [ -n "$lp_sorted" ] ; then
echo ''; echo "$less_sp" | grep -w -E -m 1 "AS${r_as}" | cut -d '|' -f 1 | sed 's/AS/AS /g' ; echo ''
lp_out=$(echo "$less_sp" | grep -w -E "AS${r_as}" | cut -d '|' -f 2 | sed 's/^ *//' | tr '[:space:]' ' ')
echo -e "$lp_out\n" | fmt -s -w 80 ; fi ; done
if [ -n "$more_sp" ] ; then
echo '' ; fi ; fi
if [ -n "$more_sp" ] ; then
echo -e "\nMore Specific\n_____________\n"
for r_as in $rel_asn ; do
mp_sorted=$(echo "$more_sp" | grep -w -E "AS${r_as}")
if [ -n "$mp_sorted" ] ; then
echo ''; echo "$more_sp" | grep -w -E -m 1 "AS${r_as}" | cut -d '|' -f 1 | sed 's/AS/AS /g' ; echo ''
mp_out=$(echo "$more_sp" | grep -w -E "AS${r_as}" | cut -d '|' -f 2 | sed 's/^ *//' | tr '[:space:]' ' ')
echo -e "$mp_out\n" | fmt -s -w 80 ; fi ; done ; fi ; fi
}
f_NETGEO(){
local s="$*"; net_ip=$(echo $s | cut -d '/' -f 1)
if ! [ -f $tempdir/netgeo.json ] ; then
curl -s https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource=${s} > $tempdir/netgeo.json ; fi
jq -r '.data.located_resources[].locations | .[] | .resources[]' $tempdir/netgeo.json | sort -u -V > $tempdir/nets_geo.list
netcount=$(cat $tempdir/nets_geo.list | wc -w); locations=$(jq -r '.data.located_resources[].locations | .[]' $tempdir/netgeo.json)
echo -e "GEOGRAPHIC DISTRIBUTION" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' > $tempdir/geo_temp
echo "$locations" | jq -r '{N: .resources[], Lat: .latitude, Lon: .longitude, cov: .covered_percentage, Country: .country, C: .city}' |
tr -d '{,"}' | sed 's/^ *//' | sed '/^$/d' | tr '[:space:]' ' ' | sed 's/N: /\n\n/g' | sed 's/ Lon: /\,/g' | sed 's/Lat:/ -  Lat\/Lon:/g' |
sed 's/cov:/(covered:/g' | sed 's/Country:/%) | Country:/g' | sed 's/C://g' >> $tempdir/geo_temp ; echo '' >> $tempdir/geo_temp
if [[ $netcount -gt "3" ]] ; then
echo -e "_______________\n" >> $tempdir/geo_temp ; cat $tempdir/nets_geo.list >> $tempdir/geo_temp  ; fi
if [[ $netcount -gt "3" ]] ; then
echo -e "\n_______________________________________\n" >> $tempdir/geo_temp
cat $tempdir/nets_geo.list | tr '[:space:]' ' ' | fmt -s -w 40 | sed 's/ /  /g' | sed 's/^ *//' >> $tempdir/geo_temp
echo '' >> $tempdir/geo_temp ; fi
if [[ $netcount -gt 41 ]] ; then
echo -e "\nOutput has been written to file ($netcount networks)" ; f_Long > $outdir/NET_GEOLOC.$net_ip.txt
cat $tempdir/geo_temp >> $outdir/NET_GEOLOC.$net_ip.txt ; else
cat $tempdir/geo_temp; fi ; rm $tempdir/netgeo.json
}
f_SUBNETS(){
local s="$*"; net_ip=$(echo $s | cut -d '/' -f 1)
if ! [ $rir = "lacnic" ] ; then
if [[ ${net_ip} =~ $REGEX_IP4 ]] && [ $rir = "ripe" ]; then
curl -s "https://stat.ripe.net/data/address-space-hierarchy/data.json?resource=${s}" > $tempdir/hierarchy.json
subnets_total=$(jq -r '.data.more_specific[] | .inetnum' $tempdir/hierarchy.json | wc -l)
jq -r '.data.more_specific[] | {Range: .inetnum, Name: .netname, Descr: .descr}' $tempdir/hierarchy.json |
tr -d '{",}' | sed 's/^ *//' | grep -w -v 'null' | tr '[:space:]' ' ' | sed 's/Range: /\n\n/g' | sed 's/Name:/|/g' | sed 's/Country:/|/g' |
sed 's/Descr:/|/g' | sed 's/Rem:/|/g' > $tempdir/subs; else
if [ $rir = "arin" ] ; then
net_handle=$(grep -E "^NetHandle:" $tempdir/whois | awk '{print $NF}' | sed 's/^ *//' | tr -d ' '); echo '' > $tempdir/subs
whois -h whois.arin.net -- "n - $net_handle" | grep '(' >> $tempdir/subs; subnets_total=$(grep '(' $tempdir/subs | wc -l); else
whois -h whois.$reg.net -- "--no-personal -M $s" > $tempdir/subs_raw
subnets_total=$(grep -E -o "^inetnum|^inet6num" $tempdir/subs_raw | wc -w)
grep -i -E "^inetnum:|^inet6num:|^netname:|^org:|^org-name:|^descr:" $tempdir/subs_raw | sed '/inetnum:/i \nnn' | sed '/netname:/i \nnn' |
sed 's/inetnum:        //g' | sed 's/netname:        //g' | sed 's/org-name:       /;/g' | sed 's/organisation:   /;/g' |
sed 's/descr:          /;/g' | tr '[:space:]' ' ' | sed 's/nnn/\n\n/g' | sed 's/^ *//' | sed 's/;/| /g' | sed '/|/G' > $tempdir/subs; fi; fi
if [[ $subnets_total -gt 0 ]] ; then
echo '' > $tempdir/subnets ; f_Long >> $tempdir/subnets
echo -e "SUBNETS: $subnets_total\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' >> $tempdir/subnets
if [[ ${net_ip} =~ $REGEX_IP4 ]] && [ $rir = "ripe" ]; then
while read line ; do
range=$(echo $line | grep '|' | cut -s -d '|' -f 1 | tr -d ' ')
if [ -n "$range" ] ; then
net_out=$(echo "$line" | cut -d '|' -f 2- | sed 's/^ *//')
cidr=$(ipcalc -r ${range} | tail -1); echo -e "$cidr  | $net_out\n"; fi
done < $tempdir/subs >> $tempdir/subnets; else
cat $tempdir/subs >> $tempdir/subnets; fi
if [[ $subnets_total -lt 41 ]] ; then
cat $tempdir/subnets; else
echo -e "Results have been written to file" ; cat $tempdir/subnets > ${outdir}/SUBNETS.$net_ip.txt ; fi; fi; fi
}

f_addressSPACE(){
local s="$*" ; net=`echo "$s" | cut -d '/' -f 1`
if [[ ${net} =~ $REGEX_IP4 ]] ; then
reg=$(curl -s "https://stat.ripe.net/data/rir/data.json?resource=${s}" | jq -r '.data.rirs[0].rir' | cut -d ' ' -f 1 | tr -d ' ' | tr [:upper:] [:lower:])
else
curl -s https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=${s} > $tempdir/ac.json
reg=$(jq -r '.data.authoritative_rir' $tempdir/ac.json); fi
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
filtered=$(cat $tempdir/whois_filtered | sed '/^$/d' | sed '/in:/{x;p;x;}' | sed '/i6:/{x;p;x;}' | sed '/--/d' | cut -d ' ' -f 2- | sed 's/^ *//')
if [ -n "$filtered" ] ; then
echo "$filtered" ; f_Short ; echo -e "* CIDR\n"
cat $tempdir/whois_filtered | grep -E -i "^i6:" $tempdir/whois_filtered | cut -d ' ' -f 2- | tr -d ' ' | fmt -s -w 20
for i in $(cat $tempdir/whois_filtered | grep "^in:" | grep -E "\-" | cut -d ' ' -f 2- | tr -d ' ') ; do
${PATH_ipcalc} ${i} | sed '/deaggregate/d' ; done ; else
echo -e "\nNo results" ; fi ; done; echo '' ; else
echo '' ; f_Short ; echo -e "More Specifcs" ; f_Short ; echo ''
cat $tempdir/whois | grep -E -a "^in:|^i6:|^na:|^de:|^og:|^or:|^rt:|^r6:|^ac:|^cy:" | sed '/in:/G' | sed '/i6:/G' |
sed '/in:/i \___________________________________________________________\n' | sed '/i6:/i \___________________________________________________________\n' |
sed '/rt:/i \___________________________________________________________\n' | sed '/r6:/i \___________________________________________________________\n' |
sed '/--/d' | cut -d ' ' -f 2- | sed 's/^ *//'
f_Short ; echo -e "* CIDR\n"
grep -E -i "^i6:" $tempdir/whois | cut -d ' ' -f 2- | tr -d ' ' | fmt -s -w 20
for i in $(cat $tempdir/whois| grep "^in:" | grep -E "\-" | cut -d ':' -f 2- | tr -d ' ') ; do
${PATH_ipcalc} "${i}" | sed '/deaggregate/d' | tail -1 ; done ; echo '' ; fi ; else
echo -e "\nNO SUPPORT FOR ARIN & LACNIC FOR NOW\n" ; fi
}
#********************** WHOIS (RIR SPECIFIC) ***********************
f_arin_WHOIS(){
local s="$*"
if  [[ ${s} =~ "/" ]] ; then
whois -h whois.arin.net r $s | grep '(' | tail -1 > $tempdir/whois_results
net_handle=$(cat $tempdir/whois_results | cut -d '(' -f 2-  | cut -d ')' -f 1 | tr -d ' ')
if [ -n "$net_handle" ] ; then 
whois -h whois.arin.net -- "n ! $net_handle" > $tempdir/whois ; fi
elif  [[ ${s} =~ $REGEX_DOMAIN ]] ; then
whois -h whois.arin.net -- "e + @$s" > $tempdir/whois; f_DNSWhois_STATUS "${s}"
elif  [[ ${s} =~ "*@*" ]] ; then
whois -h whois.arin.net -- "e + $s" > $tempdir/whois 
mail_dom=$(echo $s | cut -d '@' -f 2) ; f_DNSWhois_STATUS "${mail_dom}" ; else 
whois -h whois.arin.net z + $s > $tempdir/whois ; fi 
}
f_ARIN_ORG(){
local s="$*"; orgid=$(grep -E -a -m 1 "^OrgId:" ${s} | cut -d ':' -f 2- | sed 's/^ *//'); f_Long
echo -e "ORG: $orgid\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; orgname=$(grep -E -a -m 1 "^OrgName:" ${s} | cut -d ':' -f 2- | sed 's/^ *//')
a_address=$(grep -E -m 1 -A 8 "^OrgName:"  ${s} | grep -E "^Address:" | cut -d ':' -f 2- | sed 's/^ *//' | tr '[:space:]' ' ' ; echo '')
a_state=$(grep -s -E  -m 1 "^StateProv:" ${s} | cut -d ':' -f 2- | sed 's/^ *//')
zip=$(grep -s -E  -m 1 "^PostalCode:" ${s} | cut -d ':' -f 2- | sed 's/^ *//')
a_city=$(grep -s -E  -m 1 "^City:" ${s} | cut -d ':' -f 2- | sed 's/^ *//')
a_ctry=$(grep -s -E  -m 1 "^Country:" ${s} | cut -d ':' -f 2- | sed 's/^ *//')
echo -e "$orgname\n"
echo "$a_address" ; echo -e "$a_state-$zip $a_city, $a_ctry\n"
grep -s -i -E -m 3 "^AbuseName:|^AbusePhone:|^AbuseEmail:|^Org(AbuseName:|AbusePhone:|AbuseEmail:)" $s | cut -d ':' -f 2- | sed 's/^ *//'
grep -s -i -E -m 3 "^TechName:|^TechPhone:|^TechEmail:|^Org(TechName:|TechPhone:|TechEmail:)" $s | sed '/^OrgTechName:/{x;p;x;}' |
sed '/^TechName:/{x;p;x;}' | cut -d ':' -f 2- | sed 's/^ *//'; echo ''
if ! [ $option_detail = "1" ]; then
f_Short; grep -s -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $s | sort -u | tr '[:space:]' ' ' | fmt -s -w 50; echo '' ; fi
}
f_lacnicWHOIS(){
local s="$*" ; net_ip=$(echo $s | cut -d '/' -f 1); net_range=$(grep -E -i -m 1 "^inetnum|^inet6num:" $tempdir/whois | cut -d ' ' -f 2- | sed 's/^ *//')
created=$(grep -m 1 'created:' $tempdir/whois | cut -d ':' -f 2- | sed 's/^ *//' | sed -e :a -e 's/\(.*[0-9]\)\([0-9]\{4\}\)/\1-\2/;ta')
inetrev=$(grep -E -m 1 "^inetrev:" $tempdir/whois | cut -d ' ' -f 2- | sed 's/^ *//')
ctry=$(grep -E -i -m 1 "^country:|^cy:" $tempdir/whois | cut -d ':' -f 2- | sed 's/^ *//'); f_Long
echo "NETWORK" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; echo -e "\nNet:         $net_range | $created | LACNIC"; echo -e "\nInetrev:     $inetrev"
owner=$(grep -a -E -A 10 "^owner:" $tempdir/whois | grep -E "^owner:|^owner-c:|^country:" | sed '/owner:/i nnn' |
sed '/country:/i ,' | sed '/owner-c:/i (' | sed '/owner-c:/a )' | cut -d ' ' -f 2- | sed 's/^ *//' | tr '[:space:]' ' ' |
sed 's/nnn/\n\n/g' | sed 's/^ *//' | sed 's/ ,/,/g' | sed 's/( / (/' | sed 's/ )/)/' ; echo '')
l_mail=$(grep -E -i -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/whois | sort -uf | tr '[:space:]' ' '; echo '')
if [ $target_type = "Hop" ] ; then
echo -e "\nOwner:       $owner"; echo -e "\nContact:     $l_mail | cut -d ' ' -f -3" ; else
curl -s "https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource=${net_range}" > $tempdir/netgeo.json
netgeo=$(jq -r '.data.located_resources[].locations[] | .country' $tempdir/netgeo.json | sort -u | tr '[:space:]' ' ' ; echo '')
echo -e "\nGeo:         $netgeo (maxmind)"
f_Long; echo "OWNER" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
grep -E -A 10 "^owner:" $tempdir/whois | grep -E -a "^owner:|^owner-c:|^country:" | sed '/owner:/i nnn' | sed '/country:/i ,' | sed '/owner-c:/i (' |
sed '/owner-c:/a )' | cut -d ' ' -f 2- | sed 's/^ *//' | tr '[:space:]' ' ' | sed 's/nnn/\n\n/g' | sed 's/^ *//' | sed 's/ ,/,/g' | sed 's/( / (/' |
sed 's/ )/)/' ; echo ''
responsible=$(grep -E "^responsible" $tempdir/whois | cut -d ' ' -f 2- | sed 's/^ *//')
echo -e "\nResponsible: $responsible"
sed -n '/person:/,$p' $tempdir/whois | grep -E -a "^person:|^e-mail:|^country" | sed '/person:/i nnn' | sed '/e-mail:/i:' |
sed '/country:/i ,' | cut -d ' ' -f 2- | sed 's/^ *//' | tr '[:space:]' ' ' | sed 's/nnn/\n\n/g' | sed 's/^ *//' |
sed 's/ :/: /g' | sed 's/ ,/,/g'  ; echo '' ; f_Shorter; echo -e "$l_mail\n" | fmt -s -w 50
nsservers=$(grep -E "nserver:" $tempdir/whois | awk '{print $NF}' | tr '[:space:]' ' ' ; echo '')
if [ -n "$nsservers" ] ; then
f_Long; echo "NS SERVERS" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; echo -e "\n$nsservers\n" | fmt -s -w 80; fi
if ! [ $option_detail = "1" ]; then
f_Short; grep -s -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $s | sort -u | tr '[:space:]' ' ' | fmt -s -w 50; echo '' ; fi
f_PREFIX "${net_range}"
if [ $option_detail = "2" ] || [ $option_detail = "3" ]; then
f_netDETAILS "${net_range}"; fi; fi
}
#********************** pwhois.org ***********************
f_whoisTABLE(){
local s="$*" ; echo -e "begin\ntype=cymru" > $tempdir/addr.list ; cat ${s} >> $tempdir/addr.list ; echo "end" >> $tempdir/addr.list
netcat whois.pwhois.org 43 < $tempdir/addr.list > $tempdir/addr.txt
cat $tempdir/addr.txt  | sed '/Bulk mode; one IP/d' | sed '/ORG NAME/G' > $tempdir/whois_table.txt
}
f_pwhoisBULK(){
local s="$*" ; echo '' ; f_Long ; echo -e "begin" > $tempdir/addr.list; cat ${s} >> $tempdir/addr.list
echo "end" >> $tempdir/addr.list ; netcat whois.pwhois.org 43 < $tempdir/addr.list > $tempdir/addr.txt
cat $tempdir/addr.txt  | grep -E "^IP:|^Origin-AS:|^Prefix:|^AS-Org-Name:|^Org-Name:|^Net-Name:|^City:|^Geo-City:|^Country-Code:|^Geo-Country-Code:" |
sed '/IP:/i \_____________________\n'
}
f_netBLOCKS(){
local s="$*" ;
v4_blocks=$(whois -h whois.pwhois.org "netblock org-id=${s}" | grep '|' | cut -d '|' -f 1,2 | sed '/Net-Range/{x;p;x;G}')
v6_blocks=$(whois -h whois.pwhois.org "netblock6 org-id=${s}" | grep -s -E "^Net-(Range|Name|Handle)|^Register-Date:" |
sed '/Net-Range:/{x;p;x;}' | cut -d ' ' -f 2- | sed 's/^ *//g')
if [ -n "$v4_blocks" ] || [ -n "$v6_blocks" ] ; then
f_Long; echo "[+] $s |  NETBLOCKS  [whois.pwhois.org]"; f_Long; fi
if [ -n "$v4_blocks" ] ; then
echo -e "\nIPv4 Netblocks\n______________\n" ; echo -e "$v4_blocks\n"
ranges=$(echo "$v4_blocks" | grep '*>' | awk -F' ' '{print $2 $3 $4}')
for i in $ranges ; do
${PATH_ipcalc} "${i}" | sed '/deaggregate/d' | sed '/^$/d'; done > $tempdir/v4_ranges
if [[ $(cat $tempdir/v4_ranges | wc -w) -gt 2 ]]; then
v4_ranges=$(cat $tempdir/v4_ranges | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -s -w 60)
echo -e "\n__________________________________________________________________\n"
echo -e "$v4_ranges"; echo -e "__________________________________________________________________\n" ; else
echo '' ; cat $tempdir/v4_ranges; echo ''; fi ; fi
if [ -n "$v6_blocks" ] ; then
echo -e "\nIPv6 Netblocks\n______________\n" ; echo -e "$v6_blocks\n" ; fi
}

#********************** PREFIXES, BGP & RPKI STATUS ***********************
f_PREFIX(){
local s="$*"; net_ip=$(echo $s | cut -s -d '/' -f 1)
if [ -n "$net_ip" ]; then
prfx="$s" ; curl -s "https://stat.ripe.net/data/routing-status/data.json?resource=$s" > $tempdir/bgp.json
if [[ ${net_ip} =~ $REGEX_IP4 ]] ; then
visibility=$(jq -r '.data.visibility.v4.ris_peers_seeing' $tempdir/bgp.json); else
visibility=$(jq -r '.data.visibility.v6.ris_peers_seeing' $tempdir/bgp.json); fi
if [[ $visibility -gt 0 ]] ; then
if [ $domain_enum = "true" ] ; then
as=$(jq -r '.data.origins[0].origin' $tempdir/bgp.json); fi
curl -s -m 5 --location --request GET "https://stat.ripe.net/data/rpki-validation/data.json?resource=$as&prefix=$prfx" > $tempdir/rpki.json
f_showROAS "${prfx}"; f_showORIGIN "${as}" ; else
echo '' ; f_Long; echo "PREFIX" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; echo "$s is not announced."
more_sp=$(jq -r '.data.more_specifics[] | {AS: .origin, P: .prefix}' $tempdir/bgp.json | tr -d '{\",}' | sed 's/^ *//' | sed '/null/d' |
sed '/^$/d' | tr '[:space:]' ' ' | sed 's/AS: /\n\n/g' | sed 's/P:/ |/g')
less_sp=$(jq -r '.data.less_specifics[] | {AS: .origin, P: .prefix}' $tempdir/bgp.json | tr -d '{\",}' | sed 's/^ *//' | sed '/null/d' |
sed '/^$/d' | tr '[:space:]' ' ' | sed 's/AS: /\n\n/g' | sed 's/P:/ | /g')
if [ -n "$more_sp" ] ; then
if [[ $(jq -r '.data.more_specifics[] | .prefix' $tempdir/bgp.json | wc -w) -lt 29 ]] ; then
echo -e "\nMORE SPECIFICS"; p_rel=$(echo "$more_sp"); asn_uniq=$(jq -r '.data.more_specifics[].origin' $tempdir/bgp.json | sort -ug)
for rel_asn in $asn_uniq ; do
more_sp_sorted=$(echo "$more_sp" | grep -w -E "^$rel_asn")
if [ -n "$more_sp_sorted" ] ; then
mp_as=$(echo "$more_sp_sorted" | grep -w -E -m 1 -o "^${rel_asn}")
more_sp_out=$(echo "$more_sp_sorted" | grep -w -E "^${rel_asn}" | cut -d '|' -f 2 | sed 's/^ *//' | tr '[:space:]' ' ')
echo -e "\nAS $mp_as\n"; echo -e "$more_sp_out\n" | fmt -s -w 80 ; fi ; done ; fi 
if [ $target_type = "net" ] ; then
if [[ $(echo "$more_sp" | grep -E -o -w "${x}" | wc -w) -gt 0 ]]; then
prefix_mp="$x"; asn_mp=$(echo "$more_sp" | grep -E "${x}" | cut -d '|' -f 1 | tr -d ' '); else
prefix_mp=$(echo "$more_sp" | grep '|' | head -1 | cut -d '|' -f 2 | tr -d ' ')
asn_mp=$(echo "$more_sp" | grep '|' | head -1 | cut -d '|' -f 1 | tr -d ' '); fi; else 
prefix_mp=$(echo "$more_sp" | grep '|' | head -1 | cut -d '|' -f 2 | tr -d ' ')
asn_mp=$(echo "$more_sp" | grep '|' | head -1 | cut -d '|' -f 1 | tr -d ' '); fi ; fi 
if [ -n "$less_sp" ] ; then
if [[ $(jq -r '.data.less_specifics[] | .prefix' $tempdir/bgp.json | wc -w) -lt 29 ]] ; then
echo -e "\nLESS SPECIFICS"; asn_uniq=$(jq -r '.data.less_specifics[].origin' $tempdir/bgp.json | sort -ug)
for rel_asn in $asn_uniq ; do
lp_sorted=$(echo "$less_sp" | grep -w -E "AS${rel_asn}")
if [ -n "$less_sp_sorted" ] ; then
lp_as=$(echo "$less_sp_sorted" | grep -w -E -m 1 -o "^${rel_asn}")
less_sp_out=$(echo "$less_sp_sorted" | grep -w -E "^${rel_asn}" | cut -d '|' -f 2 | sed 's/^ *//' | tr '[:space:]' ' ')
echo -e "\nAS $lp_as\n"
echo -e "$less_sp_out\n" | fmt -s -w 80 ; fi ; done; fi
if [ $target_type = "net" ] ; then
if [[ $(echo "$less_sp" | grep -E -o -w "${x}" | wc -w) -gt 0 ]]; then
prefix_lp="$x"; asn_lp=$(echo "$less_sp" | grep -E "${x}" | cut -d '|' -f 1 | tr -d ' '); else
prefix_lp=$(echo "$less_sp" | grep '|' | head -1 | cut -d '|' -f 2 | tr -d ' ')
asn_lp=$(echo "$less_sp" | grep '|' | head -1 | cut -d '|' -f 1 | tr -d ' '); fi ; else
prefix_lp=$(echo "$less_sp" | grep '|' | head -1 | cut -d '|' -f 2 | tr -d ' ')
asn_lp=$(echo "$less_sp" | grep '|' | head -1 | cut -d '|' -f 1 | tr -d ' '); fi ; fi
if [ -n "$prefix_mp" ] && [ -n "$asn_mp" ] ; then
echo -e "\nTrying a more specific resource ...\n"
curl -s "https://stat.ripe.net/data/routing-status/data.json?resource=$prefix_mp" > $tempdir/bgp.json
curl -s -m 5 --location --request GET "https://stat.ripe.net/data/rpki-validation/data.json?resource=$asn_mp&prefix=$prefix_mp" > $tempdir/rpki.json
f_showROAS "${prefix_mp}" ; f_showORIGIN "${asn_mp}" ; fi
if [ -n "$prefix_lp" ] && [ -n "$asn_lp" ] ; then
echo -e "\nTrying a less specific resource ...\n"
curl -s "https://stat.ripe.net/data/routing-status/data.json?resource=$prefix_lp" > $tempdir/bgp.json
curl -s -m 5 --location --request GET "https://stat.ripe.net/data/rpki-validation/data.json?resource=$asn_lp&prefix=$prefix_lp" > $tempdir/rpki.json
f_showROAS "${prefix_lp}" f_showORIGIN "${asn_lp}" ; fi ; fi ; else
echo "Invalid Argument"; fi
}
f_showROAS(){
local s="$*" ; p_ip=$(echo $s | cut -d '/' -f1)
rpki_status=$(jq -r '.data.status' $tempdir/rpki.json)
roa_prefix=$(jq -r '.data.validating_roas[0].prefix' $tempdir/rpki.json)
roa_origin=$(jq -r '.data.validating_roas[0].origin' $tempdir/rpki.json)
max_length=$(jq -r '.data.validating_roas[0].max_length' $tempdir/rpki.json)
validity=$(jq -r '.data.validating_roas[0].validity' $tempdir/rpki.json)
l_seen_origin=$(jq -r '.data.last_seen.origin' $tempdir/bgp.json)
l_seen=$(jq -r '.data.last_seen.time' $tempdir/bgp.json | sed 's/T/  /g')
if [ $domain_enum = "true" ] ; then
if [[ $p_ip =~ $REGEX_IP4 ]] ; then
reverse=$(echo $p_ip | awk -F'.' '{print $4 "." $3 "." $2 "." $1}')
dig +short $reverse.origin.asn.cymru.com TXT | tr -d '"' | sed 's/^[ \t]*//;s/[ \t]*$//' > $tempdir/cymru_pfx
in_reg=$(awk -F'|' '{print $4}' $tempdir/cymru_pfx | head -1 | sed 's/^[ \t]*//;s/[ \t]*$//' | tr -d ' ')
ctry=$(awk -F'|' '{print $3}' $tempdir/cymru_pfx | head -1 | sed 's/^[ \t]*//;s/[ \t]*$//' | tr -d ' ') ; else
whois -h whois.cymru.com -- "-v -f ${s}"  > $tempdir/cymru_pfx
in_reg=$(cat $tempdir/cymru_pfx | awk -F'|' '{print $5}' | head -1 | sed 's/^[ \t]*//;s/[ \t]*$//' | tr -d ' ')
ctry=$(awk -F'|' '{print $4}' $tempdir/cymru_pfx  | head -1 | sed 's/^[ \t]*//;s/[ \t]*$//' | tr -d ' ') ; fi
f_Long; echo -n "BGP PREFIX"; echo -e "$s  ($ctry, $in_reg)\n" | sed -e :a -e 's/^.\{1,68\}$/ &/;ta' ; else
f_Long; echo -n "BGP PREFIX"; echo -e "$s\n" | sed -e :a -e 's/^.\{1,68\}$/ &/;ta' ; fi
echo -e "\nBGP:          last seen: $l_seen - AS $l_seen_origin"
echo "ROA: $rpki_status" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
if ! [ $rpki_status = "unknown" ] ; then
echo -e "ROAs:         $validity > $roa_prefix >  $roa_origin  > max. /$max_length\n" ; fi
}
f_showORIGIN(){
local s="$*" ; if [ $target_type = "hop" ] ; then
as_name=$(dig +short as$s.asn.cymru.com TXT | tr -d '"' | sed 's/^[ \t]*//;s/[ \t]*$//' | cut -d '|' -f 5 | sed 's/^ *//')
echo -e "\nASN:          $s  | $as_name\n" ; else 
f_AS_WHOIS "${s}" ; fi
}
f_ROUTE_CONS(){
local s="$*"; f_Long ; echo "BGP-WHOIS CONSISTENCY: PREFIXES" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
curl -s "https://stat.ripe.net/data/prefix-routing-consistency/data.json?resource=${s}" > $tempdir/rc.json
jq -r '.data.routes[] | {Pfx: .prefix, AS: .origin, N: .asn_name, BGP: .in_bgp, WHOIS: .in_whois}' $tempdir/rc.json | tr -d '{",}' | sed 's/^ *//' |
sed '/^$/d' | tr '[:space:]' ' ' | sed 's/Pfx: /\n\n/g' | sed 's/AS:/ | AS/g' | sed 's/N: /, /g' | sed 's/BGP:/| BGP:/g' |
sed 's/WHOIS:/| WHOIS:/g' > $tempdir/routecons ; echo '' >> $tempdir/routecons
route_incons=$(grep -E "BGP: false|WHOIS: false" $tempdir/routecons)
pfx_whois_false=$(echo "$route_incons" | grep -w "WHOIS: false" $tempdir/routecons)
pfx_bgp_false=$(echo "$route_incons" | grep -w "BGP: false" $tempdir/routecons)
consistent=$(grep -w -v "false" $tempdir/routecons | grep '|')
if [ -n "$pfx_whois_false" ] ; then
pfx_count=$(echo "$pfx_whois_false" | grep -w -c "WHOIS: false")
echo -e "\nNOT in WHOIS\n____________\n"; echo -e "$pfx_whois_false\n" | cut -d '|' -f 1,2,4 | sort -t '|' -k 1 -uV | sed '/|/G'
if [[ $pfx_count -gt "2" ]] ; then
echo -e "________________\n"; echo -e "$pfx_whois_false" | cut -d '|' -f 1 | sed 's/^[ \t]*//;s/[ \t]*$//' | sort -uV
if [ -n "$pfx_bgp_false" ] || [ -n "$consistent" ]; then
echo -e "________________\n" ; else
echo '' ; fi ; else
echo '' ; fi ; fi
if [ -n "$pfx_bgp_false" ] ; then
pfx_count=$(echo "$pfx_bgp_false" | grep -w -c "BGP: false")
echo -e "\nNOT seen in BGP\n_______________\n"; echo -e "$pfx_bgp_false\n"  | cut -d '|' -f -3 | sort -t '|' -k 1 -uV | sed '/|/G'
if [[ $pfx_count -gt "2" ]] ; then
echo -e "________________\n"
echo -e "$pfx_bgp_false"  | cut -d '|' -f 1 | sed 's/^[ \t]*//;s/[ \t]*$//' | sort -V
if [ -n "$consistent" ] ; then
echo -e "________________\n" ; else
echo '' ; fi ; else
echo '' ; fi ; fi
if [ -n "$consistent" ] ; then
echo -e "\nIn WHOIS & SEEN in BGP\n______________________\n\n"; echo -e "$consistent" | sort -t '|' -k 1 -V  | sed '/|/G' | cut -d '|' -f 1,2
pfx_count=$(echo "$consistent" | grep '|' | wc -l)
if [[ $pfx_count -gt "2" ]] ; then
echo -e "________________"; echo -e "$consistent\n" | cut -d '|' -f 1 | sed 's/^[ \t]*//;s/[ \t]*$//' | sort -V; fi ; fi
}

#********************** AS INFORMATION ***********************
f_AS_ABUSEMAIL(){
local s="$*" ; dig +short as$s.asn.cymru.com TXT | tr -d '"' | sed 's/^[ \t]*//;s/[ \t]*$//' > $tempdir/cyas
reg=$(head -1 $tempdir/cyas | awk -F'|' '{print $3}' | tr -d ' ' | sed 's/ripencc/ripe/')
asnum=$(head -1 $tempdir/cyas | awk -F'|' '{print $1}' | tr -d ' ' | sed 's/ripencc/ripe/')
asname=$(cut -d '|' -f 5 $tempdir/cyas | sed 's/^[ \t]*//;s/[ \t]*$//')
if [ $reg = "arin" ] ; then
whois -h whois.arin.net a $s > $tempdir/AS.txt
asabuse_c=`grep -s -m1 'OrgAbuseEmail:' $tempdir/AS.txt | grep -s -E -o -m 1 "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b"`
elif [ $reg = "lacnic" ] ; then
whois -h whois.lacnic.net AS${s} > $tempdir/lacnic_as.txt
asabuse_c=$(grep -s -E -o -m 1 "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/lacnic_as.txt | sort -uV | tr '[:space:]' ' ' ; echo '')
asabuse_c=$(grep -s -A 4 ${abusecon} $tempdir/lacnic_as.txt | grep -s -E -o -m 1 "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b") ; else
asabuse_c=$(whois -h whois.$reg.net -- "-b as${s}" | grep -s -E -o -m 1 "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b") ; fi ; export asabuse_c
}
f_AS_WHOIS() {
local s="$*" ; dig +short as$s.asn.cymru.com TXT | tr -d '"' | sed 's/^[ \t]*//;s/[ \t]*$//' > $tempdir/cyas
reg=$(head -1 $tempdir/cyas | awk -F'|' '{print $3}' | tr -d ' ' | sed 's/ripencc/ripe/')
asnum=$(head -1 $tempdir/cyas | awk -F'|' '{print $1}' | tr -d ' ' | sed 's/ripencc/ripe/')
if [ $reg = "arin" ] ; then
whois -h whois.arin.net a $s > $tempdir/AS.txt
elif [ $reg = "lacnic" ] ; then
whois -h whois.lacnic.net AS${s} > $tempdir/AS.txt ; else
whois -h whois.$reg.net -- "--no-personal AS${s}" > $tempdir/AS.txt; fi
asnum=$(head -1 $tempdir/cyas | awk -F'|' '{print $1}' | tr -d ' ' | sed 's/ripencc/ripe/')
as_ctry=$(cut -d '|' -f 2 $tempdir/cyas | sed 's/^[ \t]*//;s/[ \t]*$//' | head -1)
if [ $reg = "lacnic" ] ; then
asname=$(cut -d '|' -f 5 $tempdir/cyas | sed 's/^[ \t]*//;s/[ \t]*$//') ; else
asname=$(grep -E -m 1 "^as-name:|^ASName:" $tempdir/AS.txt | awk '{print $NF}' | sed 's/^ *//')
as_org=$(grep -E -m 1 "^org-name:|^OrgName:" $tempdir/AS.txt | cut -d ':' -f 2- | sed 's/^ *//')
as_org_id=$(grep -E -m 1 "^org:|^OrgId:" $tempdir/AS.txt | cut -d ':' -f 2- | sed 's/^ *//'); fi
if ! [ $reg = "lacnic" ] && ! [ $reg = "arin" ]; then
as_descr=$(grep -E "^descr:" $tempdir/AS.txt | cut -d ':' -f 2- | sed 's/^ *//' | grep -E -v "^RIPE NCC ASN block" | tail -1)
as_mnt=$(grep -E "^mnt-by:" $tempdir/AS.txt | cut -d ':' -f 2- | sed 's/^ *//' | grep -E -v "^RIPE-NCC-LEGACY-MNT|^RIPE-NCC-HM-MNT" | tail -1); fi
as_mail=$(grep -sEoa "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/AS.txt | sort -u | head -2 | tr '[:space:]' ' ' ; echo '')
if [ $reg = "lacnic" ] ; then
echo -e "\nASN:          $asnum - $asname"; echo -e "\n              $as_ctry | $reg | $as_mail" ; else
echo -e "\nASN:          $asnum | $asname - $as_org"; echo -e "\n              $as_org_id | $as_ctry | $reg | $as_mail\n"; fi
}
f_AS_SUMMARY(){
local s="$*"; f_AS_ABUSEMAIL "${s}" ; reg=$(head -1 $tempdir/cyas | awk -F'|' '{print $3}' | tr -d ' ' | sed 's/ripencc/ripe/')
curl -s "https://stat.ripe.net/data/as-overview/data.json?resource=AS${s}" > $tempdir/asov.json
f_Long ; echo "AS $s"  | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
echo -e "\nName:        $asname" ; echo "BGP:         announced: $(jq -r '.data.announced' $tempdir/asov.json)"
echo "RIR:         $(echo $reg | tr [:lower:] [:upper:])"
echo "ORG:         $(jq -r '.data.holder' $tempdir/asov.json)"; echo -e "[@]:         $asabuse_c \n"
}
f_asHEADER(){
curl -s "https://stat.ripe.net/data/as-overview/data.json?resource=AS${asnum}" > $tempdir/asov.json
echo -e "\n"; f_Long ; echo "[+]  AS $asnum  | $(jq -r '.data.holder' $tempdir/asov.json)" ; f_Long
}
f_asINFO(){
echo '' ; f_asHEADER; curl -s https://api.bgpview.io/asn/${asnum} > $tempdir/asn.json
announced=$(jq -r '.data.announced' $tempdir/asov.json); f_AS_ABUSEMAIL "${asnum}"
curl -s "https://stat.ripe.net/data/routing-status/data.json?resource=AS${asnum}" > $tempdir/status.json
curl -s -m 5 "https://api.asrank.caida.org/v2/restful/asns/${asnum}" > $tempdir/caida.json
as_descr=$(jq -r '.data.description_full[]' $tempdir/asn.json)
traffic=$(jq -r '.data.traffic_estimation' $tempdir/asn.json | sed 's/null/no data/')
ratio=$(jq -r '.data.traffic_ratio'  $tempdir/asn.json | sed 's/null/no data/')
as_size=$(jq -r '.data.announced_space.v4.ips' $tempdir/status.json | sed -e :a -e 's/\(.*[0-9]\)\([0-9]\{3\}\)/\1,\2/;ta')
pfx_v4=$(jq -r '.data.announced_space.v4.prefixes' $tempdir/status.json)
pfx_v6=$(jq -r '.data.announced_space.v6.prefixes' $tempdir/status.json)
l_glass=$(jq -r '.data.looking_glass' $tempdir/asn.json)
as_org=$(jq -r '.data.holder' $tempdir/asov.json | cut -d ' ' -f 2- | sed 's/^ *//' | sed 's/^- //')
echo "[@]: $asabuse_c" ; echo -e "____\n"
echo -e "\nName:           $(cut -d '|' -f 5 $tempdir/cyas | sed 's/^ *//')"
echo -e "\nDescription:    $(jq -r '.data.description_full[]' $tempdir/asn.json)"
if [ -n "$as_org" ] ; then
echo -e "\nOrg:            $as_org" ; fi
echo -e "\nSeen:           $announced"
echo -e "Alloc.:         $(cut -d '|' -f 4 $tempdir/cyas | sed 's/^ *//')|$(cut -d '|' -f 2,3 $tempdir/cyas)\n"
echo -e "LookingGlass:   $l_glass"
echo -e "Website:        $(jq -r '.data.website'  $tempdir/asn.json)\n"
curl -s "https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS${asnum}" > $tempdir/neigh.json
f_Short; echo -e "AS Contact" ; echo -e "__________\n"; jq -r '.data.owner_address[]' $tempdir/asn.json ; echo ''
jq -r '.data.email_contacts[]' $tempdir/asn.json ; echo ''
if [ $announced = "true" ] ; then
echo '' ; curl -s https://api.bgpview.io/asn/${asnum}/ixs > $tempdir/asix.json
f_Long; echo "STATISTICS" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
echo -e "Data Traffic\n____________\n"; echo "Ratio:          $ratio"; echo "Volume:         $traffic"
echo -e "\n\nAnnounced Address Space\n_______________________\n";
echo "IPv4 Prefixes:  $pfx_v4  (IPs: $as_size)"; echo "IPv6 Prefixes:  $pfx_v6"
echo -e "\n\nNeighbours\n__________\n"
echo "Observed:       $(jq -r '.data.observed_neighbours' $tempdir/status.json)"
echo "Unique:         $(jq -r '.data.neighbour_counts.unique' $tempdir/neigh.json)"
echo "Providers:      $(jq -r '.data.asn.asnDegree.provider' $tempdir/caida.json)"
echo "Left:           $(jq -r '.data.neighbour_counts.left' $tempdir/neigh.json)"
echo "Right:          $(jq -r '.data.neighbour_counts.right' $tempdir/neigh.json)"
echo '' ; f_Long; echo -e "ANNOUNCED PREFIXES" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; f_bgpPREFIXES ; echo ''
f_Long ; echo -e "AS $asnum  IX PRESENCE" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
asix=$(jq -r '.data[] | {IXid: .ix_id, Na: .name, Ct: .country_code, Cy: .city, Speed: .speed, IPv4: .ipv4_address, IPv6: .ipv6_address}' $tempdir/asix.json |
tr -d '{",}' | sed 's/^ *//' | sed '/^$/d' | tr '[:space:]' ' ' | sed 's/IXid:/\nID:/g' | sed 's/Na: /\n\n/g' | sed 's/Ct:/|/g' | sed 's/Cy:/|/g' |
sed 's/Speed:/| Speed:/g' | sed 's/IPv4: /\n\nIP: /g' | sed '/IP:/G' |  sed 's/IPv6://g' | sed '/IP:/G')
if [ -n "$asix" ] ; then
echo -e "$asix\n" ; else
echo -e "Unknown / NA\n" ; fi
f_Long ; echo -e "\nNEIGHBOURS" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' ; echo -e " -- Left --\n"
n_left=$(jq -r '.data.neighbours[] | .asn, .type' $tempdir/neigh.json | grep -B 1 'left' | grep -v 'left' | tr '[:space:]' ' ' | fmt -w 40 -s | sort -ug)
n_right=$(jq -r '.data.neighbours[] | .asn, .type' $tempdir/neigh.json | grep -B 1 'right' | grep -v 'right' | tr '[:space:]' ' ' |
fmt -w 40 -s | sort -ug)
echo -e "$n_left\n"
if [ -n "$n_right" ] ; then
echo -e "\n -- Right --\n" ; echo "$n_right" ; echo '' ; fi ; fi
}
f_BGPviewPREFIXES(){
f_asHEADER; announced=$(jq -r '.data.announced' $tempdir/asov.json)
if [ $announced = "true" ] ; then
curl -s https://api.bgpview.io/asn/${asnum}/prefixes  > $tempdir/pfxs.json
echo -e "\nIPv6 Prefixes\n______________"
jq -r '.data.ipv6_prefixes[] | {P: .prefix, Name: .name, Loc: .country_code, Descr: .description, ROA: .roa_status}' $tempdir/pfxs.json | sed '/null/d' |
tr -d '{",}' | sed 's/^ *//' | sed '/^$/d' | tr '[:space:]' ' ' | sed '/P:/G' | sed 's/P: /\n\n/g' | sed 's/Name: /\n\n/g' | sed 's/Descr:/|/g' |
sed 's/Loc:/|/g' | sed 's/ROA:/| ROA:/g' | sed '/|/G' ; echo ''; echo -e "\n\nIPv4 Prefixes\n______________"
jq -r '.data.ipv4_prefixes[] | {P: .prefix, Name: .name, Loc: .country_code, Descr: .description, ROA: .roa_status}' $tempdir/pfxs.json | sed '/null/d' |
tr -d '{",}' | sed 's/^ *//' | sed '/^$/d' | tr '[:space:]' ' ' | sed '/P:/G' | sed 's/P: /\n\n/g' | sed 's/Name: /\n\n/g' | sed 's/Descr:/|/g' |
sed 's/Loc:/|/g' | sed 's/ROA:/| ROA:/g' | sed '/|/G' ; echo '' ; else
echo -e "\nAS is not announced\n" ; fi
}
f_bgpPREFIXES(){
announced=$(jq -r '.data.announced' $tempdir/asov.json)
if [ $announced = "true" ] ; then
curl -s "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS$asnum" > $tempdir/pfx.json
pfxv6=$(jq -r '.data.prefixes[] | .prefix' $tempdir/pfx.json | grep -E "*.:.*")
if [ -n "$pfxv6" ] ; then
echo -e "\n -- IPv6 --\n" ; echo "$pfxv6" | sort -V | tr '[:space:]' ' ' | sed 's/ /  /g' | fmt -w 40 -s ; echo '' ; fi
echo -e "\n -- IPv4 --\n" ; jq -r '.data.prefixes[] | .prefix' $tempdir/pfx.json | grep -E -v "*.:.*" |
sort -V | tr '[:space:]' ' ' | sed 's/ /   /g' | fmt -w 40 -s ; else
echo -e "\nAS is not announced\n" ; fi
}
f_PEERING(){
f_asHEADER; announced=$(jq -r '.data.announced' $tempdir/asov.json)
if [ $announced = "true" ] ; then
echo -e "\n* AS $asnum Peers\n"
curl -s https://api.bgpview.io/asn/${asnum}/peers > $tempdir/peers.json ; echo -e "\nPeers, v4\n__________\n"
jq -r '.data.ipv4_peers | .[] | .asn, .name, .description, .country_code' $tempdir/peers.json | sed 'n;n;n;G'
echo -e "\nPeers, v6\n__________\n"
jq -r '.data.ipv6_peers | .[] | .asn, .name, .description, .country_code' $tempdir/peers.json | sed 'n;n;n;G' ; else
echo -e "\nAS is not announced\n" ; fi
}
f_AS_ROUTING_Cons(){
f_asHEADER; announced=$(jq -r '.data.announced' $tempdir/asov.json)
if [ $announced = "true" ] ; then
curl -s "https://stat.ripe.net/data/as-routing-consistency/data.json?resource=as${asnum}" > $tempdir/ascons.json
jq -r '.data.prefixes[] | {Pfx: .prefix, in_BGP:  .in_bgp, in_Whois: .in_whois}' $tempdir/ascons.json | tr -d '{",}' |
sed 's/^ *//' | sed '/^$/d' | tr '[:space:]' ' ' | sed 's/Pfx:/\n\n*> /g' | sed 's/in_Whois:/ | WHOIS:/g' |
sed 's/in_BGP:/ | BGP:/g' > $tempdir/ascons ; echo '' >> $tempdir/ascons
pfx_whois_false=$(grep -E "WHOIS: false" $tempdir/ascons)
pfx_bgp_false=$(grep -E "BGP: false" $tempdir/ascons)
pfx_ok=$(grep -v 'false' $tempdir/ascons)
echo -e "\nBGP-WHOIS CONSISTENCY - PREFIXES" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
if [ -n "$pfx_whois_false" ] || [ -n "$pfx_bgp_false" ] ; then
if [ -n "$pfx_whois_false" ] ; then
echo -e "\nNOT in WHOIS\n____________"
pfx4=$(echo "$pfx_whois_false" | awk -F'|' '{print $1}' | sed 's/*> //g' | sed 's/^ *//' | tr -d ' ' | grep -v ":" | sort -uV |
tr '[:space:]' ' ' | fmt -s -w 40 | sed 's/ /  /g')
if [ -n "$pfx4" ] ; then
echo -e "\n$pfx4\n" ; fi
pfx6=$(echo "$pfx_whois_false" | awk -F'|' '{print $1}' | sed 's/*> //g' | sed 's/^ *//' | tr -d ' ' | grep ":" | sort -uV |
tr '[:space:]' ' ' | fmt -s -w 40 | sed 's/ /  /g' | sed 's/^ *//')
if [ -n "$pfx6" ] ; then
echo -e "\n$pfx6\n" ; fi ; fi
if [ -n "$pfx_bgp_false" ] ; then
echo -e "\nNOT seen in BGP\n_______________"
pfx4=$(echo "$pfx_bgp_false" | awk -F'|' '{print $1}' | sed 's/*> //g' | sed 's/^ *//' | tr -d ' ' | grep -v ":" | sort -uV |
tr '[:space:]' ' ' | fmt -s -w 40 | sed 's/ /  /g')
if [ -n "$pfx4" ] ; then
echo -e "\n$pfx4\n" ; fi
pfx6=$(echo "$pfx_bgp_false" | awk -F'|' '{print $1}' | sed 's/*> //g' | sed 's/^ *//' | tr -d ' ' | grep ":" | sort -uV |
tr '[:space:]' ' ' | fmt -s -w 40 | sed 's/ /  /g' | sed 's/^ *//')
if [ -n "$pfx6" ] ; then
echo -e "\n$pfx6\n" ; fi ; fi
if [ -n "$pfx_ok" ] ; then
if [ -n "$pfx_whois_false" ] || [ -n "$pfx_bgp_false" ] ; then
echo '' ; fi
echo -e "\nIn WHOIS & SEEN in BGP\n______________________"
pfx4=$(echo "$pfx_ok" | awk -F'|' '{print $1}' | sed 's/*> //g' | sed 's/^ *//' | tr -d ' ' | grep -v ":" | sort -uV |
tr '[:space:]' ' ' | fmt -s -w 40 | sed 's/ /  /g' | sed 's/^ *//')
pfx6=$(echo "$pfx_ok" | awk -F'|' '{print $1}' | sed 's/*> //g' | sed 's/^ *//' | tr -d ' ' | grep ":" | sort -uV |
tr '[:space:]' ' ' | fmt -s -w 40 | sed 's/ /  /g' | sed 's/^ *//')
if [ -n "$pfx4" ] ; then
echo -e "\n$pfx4\n" ; fi
if [ -n "$pfx6" ] ; then
echo -e "\n$pfx6\n" ; fi ; fi ; else
echo -e "\nNo inconsistencies found for IPv4 and IPv6 prefixes\n" ; fi
curl -s "https://stat.ripe.net/data/reverse-dns-consistency/data.json?resource=AS${asnum}" > $tempdir/dnscons.json
f_Long ; echo "WHOIS - rDNS DELEGATIONS CONSISTENCY" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
jq -r '.data.prefixes.ipv4' $tempdir/dnscons.json > $tempdir/dnscons4
jq -r '.data.prefixes.ipv6' $tempdir/dnscons.json > $tempdir/dnscons6
dnscons4=$(cat $tempdir/dnscons4 | tr -d '][}{,"' | sed 's/^ *//' | sed '/^$/d' | tr '[:space:]' ' ' | sed 's/domains:/DOMAINS:\n\n/' |
sed 's/domain: /\n/g' | sed 's/prefix:/ - /g' | sed 's/found:/ > /g' | sed 's/true/true\n/g' |
sed 's/false/false\n/g' | sed 's/complete:/\n\n\ncomplete:/g')
dnscons6=$(cat $tempdir/dnscons6 | tr -d '][}{,"' | sed 's/^ *//' | sed '/^$/d' | tr '[:space:]' ' ' | sed 's/domains:/DOMAINS:\n\n/' |
sed 's/domain: /\n/g' | sed 's/prefix:/ - /g' | sed 's/found:/ > /g' | sed 's/true/true\n/g' | sed 's/false/false\n/g' |
sed 's/complete:/\n\n\ncomplete:/g')
dnscons4_false=$(jq -r '.data.prefixes.ipv4' $tempdir/dnscons.json | tr -d '{\"},][' | sed 's/^[ \t]*//;s/[ \t]*$//' |
sed '/^$/d' | sed '/complete:/G' | grep -B 1 "complete: false" | grep -v 'complete:' | sed '/--/d' | sed '/^$/d' | sed 's/:$//' | sort -uV)
dnscons6_false=$(jq -r '.data.prefixes.ipv6' $tempdir/dnscons.json | tr -d '{\"},][' | sed 's/^[ \t]*//;s/[ \t]*$//' |
sed '/^$/d' | sed '/complete:/G' | grep -B 1 "complete: false" | grep -v 'complete:' | sed '/--/d' | sed 's/:$//' | sort -uV)
if [ -n "$dnscons4_false" ] || [ -n "$dnscons6_false" ] ; then
echo -e "\n+ Incomplete WHOIS entries found for:\n"
if [ -n "$dnscons4_false" ] ; then
echo -e "$dnscons4_false" | sed 's/:$//g' ; fi
if [ -n "$dnscons6_false" ] ; then
echo -e "$dnscons6_false" | sed 's/:$//g' ; fi ; echo ''
if [ -n "$dnscons4_false" ] ; then
echo "$dnscons4" | grep -v 'complete:' | grep 'false' | cut -d '>' -f 1
if [ -n "$dnscons6_false" ] ; then
echo -e "\n"; fi ; fi
if [ -n "$dnscons6_false" ] ; then
echo "$dnscons6" | grep -v 'complete:' | grep 'false' | cut -d '>' -f 1 ; fi ; else
echo -e "\n\nNo inconsistencies found for reverse DNS delegations\n" ; fi
exports_ok=$(jq -r '.data.exports[] | {Peer: .peer, BGP: .in_bgp, WHOIS: .in_whois}' $tempdir/ascons.json | tr -d '{",}' | sed 's/^ *//' | sed '/^$/d' |
tr '[:space:]' ' ' | sed 's/Peer:/\n\nPeer:/g' | sed 's/BGP:/| BGP:/g' | sed 's/WHOIS:/| WHOIS:/g' | grep -w -v "WHOIS: false" |  grep -w -v "BGP: false" |
grep 'true' | cut -d ':' -f 2- | cut -d '|' -f 1 | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d')
imports_ok=$(jq -r '.data.imports[] | {Peer: .peer, BGP: .in_bgp, WHOIS: .in_whois}' $tempdir/ascons.json | tr -d '{",}' | sed 's/^ *//' | sed '/^$/d' |
tr '[:space:]' ' ' | sed 's/Peer:/\n\nPeer:/g' | sed 's/BGP:/| BGP:/g' | sed 's/WHOIS:/| WHOIS:/g' | grep -w -v "WHOIS: false" |  grep -w -v "BGP: false" |
grep 'true' | cut -d ':' -f 2- | cut -d '|' -f 1 | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d')
exports_bgp=$(jq -r '.data.exports[] | {Peer: .peer, BGP: .in_bgp}' $tempdir/ascons.json | tr -d '{",}' | sed 's/^ *//' | sed '/^$/d' |
tr '[:space:]' ' ' | sed 's/Peer:/\n\nPeer:/g' | sed 's/BGP:/| BGP:/g' ; echo '')
exports_whois=$(jq -r '.data.exports[] | {Peer: .peer, WHOIS: .in_whois}' $tempdir/ascons.json | tr -d '{",}' | sed 's/^ *//' | sed '/^$/d' |
tr '[:space:]' ' ' | sed 's/Peer:/\n\nPeer:/' | sed 's/WHOIS:/| WHOIS:/g'; echo '')
imports_bgp=$(jq -r '.data.imports[] | {Peer: .peer, BGP: .in_bgp}' $tempdir/ascons.json | tr -d '{",}' | sed 's/^ *//' | sed '/^$/d' |
tr '[:space:]' ' ' | sed 's/Peer:/\n\nPeer:/g' | sed 's/BGP:/| BGP:/g'; echo '')
imports_whois=$(jq -r '.data.imports[] | {Peer: .peer, WHOIS: .in_whois}' $tempdir/ascons.json | tr -d '{",}' | sed 's/^ *//' | sed '/^$/d' |
tr '[:space:]' ' ' | sed 's/Peer:/\n\nPeer:/g' | sed 's/WHOIS:/| WHOIS:/g'; echo '')
imports_whois_false=$(echo "$imports_whois" | grep -w "WHOIS: false" | grep -v 'true'); imports_bgp_false=$(echo "$imports_bgp" | grep "BGP: false")
exports_whois_false=$(echo "$exports_whois" | grep -w "WHOIS: false"| grep -v 'true'); exports_bgp_false=$(echo "$exports_bgp" | grep "BGP: false")
echo '' ; f_Long ; echo "BGP-WHOIS CONSISTENCY - IMPORTS" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
echo -e "\nNOT in WHOIS\n____________\n"
if [ -n "$imports_whois_false" ] ; then
echo "$imports_whois_false" | cut -d ':' -f 2- | cut -d '|' -f 1 | sort -ug | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' |
tr '[:space:]' ' ' | fmt -s -w 40 ; echo '' ; else
echo -e "NA\n" ; fi
echo -e "\nNOT seen in BGP\n_______________\n"
if [ -n "$imports_bgp_false" ] ; then
echo "$imports_bgp_false" | cut -d ':' -f 2- | cut -d '|' -f 1 | sort -ug | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' |
tr '[:space:]' ' ' | fmt -s -w 40 ; echo '' ; else
echo -e "NA\n" ; fi
if [ -n "$imports_ok" ] ; then
echo -e "\nOK\n"; echo "$imports_ok" | tr '[:space:]' ' ' | fmt -s -w 40 ; echo '' ; fi
echo ''; f_Long ; echo "BGP-WHOIS CONSISTENCY - EXPORTS" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
echo -e "\nNOT in WHOIS\n____________\n"
if [ -n "$exports_whois_false" ] ; then
echo "$exports_whois_false" | cut -d ':' -f 2- | cut -d '|' -f 1 | sort -ug | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' |
tr '[:space:]' ' ' | fmt -s -w 40 ; echo '' ; else
echo -e "NA\n" ; fi
echo -e "\nNOT seen in BGP\n_______________\n"
if [ -n "$exports_bgp_false" ] ; then
echo "$exports_bgp_false" | cut -d ':' -f 2- | cut -d '|' -f 1 | sort -ug | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' |
tr '[:space:]' ' ' | fmt -s -w 40 ; echo '' ; else
echo -e "NA\n" ; fi
if [ -n "$exports_ok" ] ; then
echo -e "\nOK\n"; echo "$exports_ok" | tr '[:space:]' ' ' | fmt -s -w 40 ; echo '' ; fi ; fi
}

#*****************  SUBMENUS *****************
f_optionsAS(){
echo -e "\n ${B}Options > AUTONOMOUS SYSTEMS ${D}\n"
echo -e " ${B}[1]${D}  AS & Announced Prefixes ${bold}Summary${D}"
echo -e " ${B}[2]${D}  AS ${bold}Details${D}"
echo -e " ${B}[3]${D}  Announced Prefixes"
echo -e " ${B}[4]${D}  AS Peers"
echo -e " ${B}[5]${D}  Whois <> Address Space Consistency Check"
echo -e "\n ${B}[b]${D}  Back to the Global ${G2}Options Menu${D}\n"
}
f_optionsDNS(){
echo -e "\n ${B}Options > DNS ${D}\n"
echo -e " ${B}[1]${D}  Domain DNS Records"
echo -e " ${B}[2]${D}  Shared Name Servers"
if [ $option_connect = "0" ] ; then
echo -e " ${B}[3]${D}  Zone Transfer" ; else
echo -e " ${B}[3]${D}  Zone Transfer, Zone Walk" ; fi
echo -e " ${B}[4]${D}  Name Server Health Check"
echo -e " ${B}[5]${D}  MX SSL Status & Ciphers"
echo -e " ${B}[6]${D}  dig Batch Mode (Mass DNS Lookup) $denied"
echo -e " ${B}[b]${D}  Back to the Global ${G2}Options Menu${D}\n"
}
f_optionsHOSTSv4(){
echo -e "\n ${B}Options > IP ADDRESS INFORMATION  ${G2}(IPV4)\n"
echo -e " ${B}[1]${D}  Hostname / IPv4 Address ${bold}Overview${D} (Geolocation, DNS, Prefix, Whois Summary)"
echo -e " ${B}[2]${D}  ${bold}Customize${D} Options (e.g. Banners, IP Reputation, Contact or Network Details)"
echo -e " ${B}[3]${D}  Send TestPing via hackertarget.com API (API key required)"
echo -e " ${B}[4]${D}  Virtual Hosts"
echo -e " ${B}[b]${D}  Back to the Global ${G2}Options Menu${D}\n"
}
f_optionsHOSTNAME(){
echo -e "\n ${B}Options > Look up Host Information by Host Name  ${G2}(IPV4)\n"
echo -e " ${B}[1]${D}  Hostname/IP ${bold}Overview${D} (Geolocation, DNS, Prefix, Whois Summary)"
echo -e " ${B}[2]${D}  ${bold}Customize${D} Options (e.g. Banners, WhatWeb, IP Reputation, Certificates (via certspotter), Whois Contact Details)"
}
f_optionsHOSTSv6(){
echo -e "\n ${B}Options > IP ADDRESS INFORMATION  ${G2}(IPV6)\n"
echo -e " ${B}[1]${D}  IP Address Info (Geolocation, RDNS, Prefix BGP Status, Whois Summary)"
echo -e " ${B}[2]${D}  IP Address Info, Whois Contact Details"
echo -e " ${B}[3]${D}  THC-Ping6 ICMPv6/TCP Packet Builder $denied"
echo -e " ${B}[b]${D}  Back to the Global ${G2}Options Menu${D}\n"
}
f_optionsLAN(){
echo -e "\n ${B}Options > LOCAL NETWORK OPTIONS (TOOL: NMAP) ${D} $denied\n"
echo -e " ${B}[1]${D}  Send ARP Broadcast (Host Discovery)" 
echo -e " ${B}[2]${D}  Send DHCP Discover Broadcast  ${B}(IPv4)"
echo -e " ${B}[3]${D}  Send RIP2 Discover Broadcast  ${B}(IPv4)"
echo -e " ${B}[4]${D}  Send OSPF2 Discover Broadcast  ${B}(IPv4)"
echo -e " ${B}[5]${D}  Discover Network & SCADA Services  ${B}(IPv4)"
echo -e "\n ${B}Options > LOCAL NETWORKS ${B}(IPv6) ${D} $denied\n"
echo -e " ${B}[6]${D}  IPv6 Router & DHCP Overview"
echo -e "\n ${B}[b]${D}  Back to the Global ${G2}Options Menu${D}\n"
}
f_optionsNET(){
echo -e "\n\n ${B}Options > NETWORKS\n"
echo -e " ${B}[1]${D}  Network ${bold}Summary${D} (Whois, BGP- & RPKI Status)"
echo -e " ${B}[2]${D}  Generate Network ${bold}Report${D}  ${B}(IPv4)${D} $denied"
echo -e " ${B}[3]${D}  ${bold}Customize${D} Options (e.g. BGP-Whois Consistency, Geolocoation, Related Networks, Contact Details)"
echo -e " ${B}[4]${D}  Prefix Address Space (More Specifics/Subnets)"
if [ $option_type = "2" ] ; then
echo -e " ${B}[5]${D}  Reverse DNS Lookup (max-size: /48)"; else
echo -e " ${B}[5]${D}  Reverse DNS Lookup"; fi
echo -e " ${B}[6]${D}  Reverse IP Lookup (Virtual Hosts)  ${B}(IPv4)${D}"
echo -e " ${B}[8]${D}  Ping Sweep  ${B}(IPv4)${D} $denied"
echo -e "\n ${B}[b]${D}  Back to the Global ${G2}Options Menu${D}\n"
}
f_optionsWHOIS(){
echo -e "\n ${B}Options > WHOIS ${D}\n"
echo -e " ${B}[1]${G2} RIPE|AFRINIC|APNIC ${B}>${D}  Organisations, Networks & PoCs (inverse & regular searches)"
echo -e " ${B}[2]${G2} ARIN               ${B}>${D}  Organisations, Networks & PoCs"
echo -e " ${B}[3]${G2} pwhois.org         ${B}>${D}  Org & NetBlock Searches"
echo -e " ${B}[4]${G2} pwhois.org         ${B}>${D}  Whois Bulk Lookup (file input)"
echo -e "\n ${B}[b]${D} Back to the Global ${G2}Options Menu${D}" ; echo ''
}
f_optionsWWW(){
echo -e "\n${B}Options > WEB SERVERS $denied\n"
echo -e "${B} [1]${D}  Quick ${bold}Health Check${D}  (Ping, SSL (Ciphers, Basic Vulners), Response & Page-Loading-Times, Security Headers, Website Hash)"
echo -e "${B} [2]${D}  ${bold}Customize${D} Test Options (Vulnerabilities, SSL Configs, Connectivity & Server Response)"
echo -e "${B} [3]${D}  Website Overview (Markup,Contacts,Description)"
echo -e "${B} [4]${D}  Dump HTTP Headers"; echo -e "${B} [5]${D}  Dump SSL Certificate Files"
echo -e "${B} [b]${D}  Back to the Global ${G2}Options Menu${D}" ; echo ''
}
f_options_P(){
echo -e "\n ${B}Options > NMAP PORT SCANS${D}\n"
echo -e " ${B}[p1]${D}  Port-, OS/Version- & Vulnerability Scans $denied"
echo -e " ${B}[p2]${D}  Port Scan via hackertarget.com IP ${B}(hackertarget.com IP API, IPv4 support only)"
echo -e " ${B}[p3]${D}  Firewalk & Basic Firewall Evasion Options (TCP Flags, Fragmentation, Source Port Spoofing) $denied"
echo -e "\n ${B}[b]${D}   Back to the Global Options ${G2}Menu${D}\n"
}
f_options_T(){
echo -e "\n ${B}Options > TRACEROUTING & MTU DISCOVERY ${D}\n"
echo -e " ${B}[t1]  NMAP  ${D}            Path-MTU Discovery $denied"
echo -e " ${B}[t2]  Tracepath${D}         (traceroute & MTUs, non-root) $denied"
echo -e " ${B}[t3]  MTR${D}               (RT-Times, Packet Loss, Jitter; TCP,UDP,ICMP) $denied"
echo -e " ${B}[t4]  MTR${D}               (hackertarget.com IP API, IPv4 support only)"
echo -e " ${B}[t5]  Nmap${D}              (TCP Traceroute & MaxMind Geolocation Data) $denied"
echo -e " ${B}[t6]  atk-trace6${D}        (ICMPv6 Traceroute MTU- & Tunnel-Discovery) $denied"
echo -e " ${B}[t7]  Dublin Traceroute${D} (NAT-aware, Multipath Tracerouting) $denied"
echo -e " ${B}[b]${D}                     Back to the Global ${G2}Options Menu${D}"
echo -e "\n ${G2}*    ${B}Additional Options > ${G2}t1), t3), t6)${D} ROA Validation, Geolocation & whois Summary for each Hop"
echo '' ; f_Long
}

#***************************** main program loop *****************************
while true
do
echo -e -n "\n  ${B}?${D}  " ; read choice
if [ $option_connect = "0" ] ; then
denied="available in target-connect-mode only)" ; else
denied='' ; fi
case $choice in
m)
f_startMenu
;;
h|help|all|about)
#************** ABOUT / HELP  *******************
echo -e "${B}" ; f_Long
echo -e "\n ---------------" ; echo -e "  drwho.sh" ; echo -e " ---------------\n"
echo -e "https://github.com/ThomasPWy/drwho.sh,  Author: Thomas Wy,  Version: 2.0 (Dec 2021)"; f_Long ; echo -e "${D}"
echo -e "${G2}Dependencies ${D}"
echo -e "\nDependencies (essential): \n\ncurl, dnsutils (installs dig & host), jq, ipcalc, lynx, nmap, openssl, whois"
echo -e "\n\nDependencies (recommended): \n\ndublin-traceroute, lbd, mtr, sslscan, testssl, thc-ipv6, tracepath ('iputils-tracepath' in Debian/Ubuntu, 'tracepath' in Termux), wfuzz, whatweb"
echo -e "${B}" ; f_Long 
echo -e "${G2}CUSTOMIZATIONS ${D}\n"
echo -e "\n\n${B}API KEYS ${D}\n"
echo -e "Please enter your API-Keys in the designated fields right at the top (Lines 2+) of the drwho.sh-File.\n"
echo -e "An API key is required for usage of Project Honeypot's API. For more information visit: https://www.projecthoneypot.org/"
echo -e "\nAn API key for hackertarget's IP API is highly recommended (and required for the nping API) Without API key, there's a limit of 50 API calls/day."
echo -e "\nFor more information visit: https://hackertarget.com/"
echo -e "\n\n${B}EXECUTABLES ${D}\n"
echo -e "\nCustom paths to executables of dependencies can be set below the API-key field."
echo -e "${B}" ; f_Long 
echo -e "  ${G2}Target Categories >\n\n" ; echo -e "${B}   a)  ${D}Abuse Contact Finder"
echo -e "${B}  as)  ${D}ASN\n" ; echo -e "${B}  bl)  ${D}IP Reputation & Blocklist Check (IPv4-Networks & -Hosts)\n"
echo -e "${B}   d)  ${D}Domain Reconaissance)" ; echo -e "${B} dns)  ${D}DNS Records, NS- & MX Server\n"
echo -e "${B}   g)  ${D}Rev. GoogleAnalytics Search\n"; echo -e "${B}   i)  ${D}Network Interfaces & Public IP Information"
echo -e "${B}  ip)  ${D}IP Address / Hostname"; echo -e "${B}  ix)  ${D}Internet Exchange (IX)\n"; echo -e "${B}   l)  ${D}LAN\n"
echo -e "${B}   n)  ${D}Network\n" ; echo -e "${B}   p)  ${D}Port Scanning\n"
echo -e "${B}   t)  ${D}Tracerouting\n" ; echo -e "${B}   w)  ${D}Whois (inverse, organization- & bulk lookup options)"
echo -e "${B} www)  ${D}Web Server\n"
echo -e "${B}"; f_Long ; echo -e "\n\n${B}Options > AUTONOMOUS SYSTEMS ${D}\n\n"
echo -e " ${B}[1]${D}  AS & Announced Prefixes Summary"
echo -e " ${B}[2]${D}  AS Details"
echo -e " ${B}[3]${D}  Announced Prefixes"
echo -e " ${B}[4]${D}  AS Peers"
echo -e " ${B}[5]${D}  Whois <> Address Space Consistency Checks"
echo -e "\n\n ${B}Options > DNS ${D}\n\n"
echo -e " ${B}[1]${D}  Domain DNS Records"
echo -e " ${B}[2]${D}  Shared Name Servers"
echo -e " ${B}[3]${D}  Zone Transfer, Zone Walk"
echo -e " ${B}[4]${D}  Name Server Health Check"
echo -e " ${B}[5]${D}  MX SSL Status & Ciphers"
echo -e " ${B}[6]${D}  dig Batch Mode (Mass DNS Lookup)"
echo -e "\n\n ${B}Options > IP ADDRESS INFORMATION\n\n"
echo -e " ${B}[1]${D}  Hostname/IP Overview\n      (Geolocation, DNS, Prefix, Whois Summary)\n"
echo -e " ${B}[2]${D}  Customize Options\n      (e.g. Banners, IP Reputation, Contact or Network Details)\n"
echo -e " ${B}[3]${D}  Send TestPing via API ${B}(IPv4)"
echo -e " ${B}[3]${D}  THC-Ping6 ICMPv6/TCP Packet Builder ${B}(IPv6)"
echo -e " ${B}[4]${D}  Virtual Hosts (Reverse IP) ${B}(IPv4)"
echo -e "\n\n ${B}Options > NETWORKS\n\n"
echo -e " ${B}[1]${D}  Network Summary\n      Whois, BGP- & RPKI Status\n"
echo -e " ${B}[2]${D}  Generate Network Report ${B}(IPv4)"
echo -e " ${B}[3]${D}  Customize Options\n      (BGP-Whois Consistency, Geolocoation, Related Networks, Contact Details)"
echo -e " ${B}[4]${D}  Prefix Address Space (More Specifics/Subnets)"
echo -e " ${B}[5]${D}  Reverse DNS Lookup ${B}(IPv4)"
echo -e " ${B}[5]${D}  Reverse DNS Lookup  (max-size: /48) ${B}(IPv6)"
echo -e " ${B}[6]${D}  Reverse IP Lookup (Virtual Hosts) ${B}(IPv4)"
echo -e " ${B}[7]${D}  Network Services Banners ${B}(IPv4)"
echo -e " ${B}[8]${D}  Ping Sweep ${B}(IPv4)"
echo -e "\n\n${B}Options > WEB SERVERS\n\n"
echo -e "${B} [1]${D}  Quick ${bold}Health Check${D}\n      Ping, SSL (Ciphers, Basic Vulners), Response & Page-Loading-Times, Security Headers, Website Hash\n"
echo -e "${B} [2]${D}  ${bold}Customize${D} Test Options\n      Vulnerabilities, SSL Configs, Connectivity & Server Response\n"
echo -e "${B} [3]${D}  Website Overview  (Markup,Contacts,Description)"
echo -e "${B} [4]${D}  Dump HTTP Headers"; echo -e "${B} [5]${D}  Dump SSL Certificate Files"
echo -e "\n\n ${B}Options > WHOIS ${D}\n\n"
echo -e " ${B}[1]${G2} RIPE|AFRINIC|APNIC ${B}>${D}  Organisations, Networks & PoCs (inverse & regular searches)\n"
echo -e "(This option is designed for object searches - whois lookups for IP addreses and networks are covered by\nthe network & host options above)"
echo -e "\nBy default, this options performs regular lookups. For inverse searches\nenter the object type (e.g. admin-c) and, separated by semicolon, the object name (e.g. BOFH-RIPE."
echo -e "A successful search for admin-c;BOFH-RIPE should then return any resource (networks, orgs...) where BOFH-RIPE is \nserving as admin contact."
echo -e "\nInverse search objects have to be unique identifiers (no proper names) of a specified type (nic-handle is not searchable!)."
echo -e "Searching by abuse-c, admin-c, mnt-by, org & tech-c objects is usually most promising.\n"
echo -e "To maximize the yield, options [1] & [2] run a pwhois.org netblock search for any org-object found\n" 
echo -e " ${B}[2]${G2} ARIN               ${B}>${D}  Organisations, Networks & PoCs\n"
echo -e "Expects network addresses (cidr), nethandles, org-ids & e-mail domains (e.g. @ibm.com)\nand returns PoCs, Netranges, Network  & Org-Infos."
echo -e "\n ${B}[3]${G2} pwhois.org         ${B}>${D}  Org & NetBlock Searches"
echo -e " ${B}[4]${G2} pwhois.org         ${B}>${D}  Whois Bulk Lookup (file input)"
echo -e "\nVery fast mass look up for any (announced!) resource (expected input: file with IP and CIDRs, separated by new line."
echo -e "\n\n ${B}Options > NMAP PORT SCANS${D}\n\n"
echo -e " ${B}[p1]${D}  Port-, OS/Version- & Vulnerability Scans"
echo -e " ${B}[p2]${D}  Port Scan via hackertarget.com IP (API) ${B}(IPv4)"
echo -e " ${B}[p3]${D}  Firewalk & Basic Firewall Evasion Options (TCP Flags, Fragmentation, Source Port Spoofing)"
echo -e "\n\n ${B}Options > TRACEROUTING & MTU DISCOVERY ${D}\n\n"
echo -e " ${G2}[t1]  NMAP  ${D}            Path-MTU Discovery ${B}(IPv4)"
echo -e " ${G2}[t2]  Tracepath${D}         (traceroute & MTUs, non-root)"
echo -e " ${G2}[t3]  MTR${D}               (RT-Times, Packet Loss, Jitter; TCP,UDP,ICMP)"
echo -e " ${G2}[t4]  MTR${D}               (API) ${B}(IPv4)"
echo -e " ${G2}[t5]  Nmap${D}              (TCP Traceroute & MaxMind Geolocation Data)"
echo -e " ${G2}[t6]  atk-trace6${D}        (ICMPv6 Traceroute MTU- & Tunnel-Discovery) ${B}(IPv4)"
echo -e " ${G2}[t7]  Dublin Traceroute${D} (NAT-aware, Multipath Tracerouting)"
echo -e "${B}"; f_Long; echo -e "\nSources (APIs und whois Servers)${D}\n\n"
echo -e "abusix.com, bgpview.io, certspotter.com, crt.sh,\nhackertarget.com, ip-api.com, isc.sans.edu/api/ip, isc.sans.edu/api/ipdetails"
echo -e "Project Honeypot (https://www.projecthoneypot.org), ripeSTAT Data API (https://stat.ripe.net) \nSublist3r API (https://api.sublist3r.com)"
echo -e "whois.cymru.com, whois.pwhois.org \nRIR whois Servers (whois.afrinic.net, whois.apnic.net, whois.arin.net, whois.lacnic.net, whois.ripe.net)"
echo ''; f_Menu
;;
o|b|options) f_Menu ;;
cc|clear)
clear ; f_Menu
;;
#************** TOGGLE CONNECT/NON-CONNECT-MODES *******************
c|con|connect) echo '' ; f_Long; f_targetCONNECT; echo '' ; f_Menu
;;
s | r)
#************** ADD Permanent Folder  *******************
f_makeNewDir ; f_Long ; f_REPORT ; f_Menu
;;
#************** ABUSE CONTACT FINDER  *******************
a|ab|abuse|abusec|abusemail|contact|finder|abusefinder)
f_makeNewDir ; target_type="other" ; echo ''
out="${outdir}ABUSE_CONTACTS.txt" f_Long; echo -e "[+] ABUSE CONTACT FINDER"; f_Long
echo -e -n "\n${B}INPUT >${G2}  IP ADDRESS, NETWORK ADDRESS (CIDR), ASN (e.g. as101) ${B}>>${D}  " ; read input
f_abuse_cFINDER "${input}" | tee -a ${out} ; f_removeDir ; f_Menu
;;
#************** AUTONOMOUS SYSTEMS INFORMATION  *******************
as|asn|asnum)
f_makeNewDir ; f_Long ; f_optionsAS; echo -e -n "\n  ${B}?${D}  " ; read option_as
if ! [ $option_as = "b" ] ; then
if [ $option_as = "1" ] ; then
echo -e "\n${B}Options > AS Summary\n"
echo -e "${B} [1]${D} AS Summary" ; echo -e "${B} [2]${D} Announced Prefixes"
echo -e "${B} [3]${D} BOTH" ; echo -e -n "\n  ${B}?${D}  " ; read option_as1
echo -e -n "\n${B}Target > [1]${D}  Set Target ${B}| [2]${D}  Target List  ${B}?${D}  " ; read option_target
if [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target > ${G2}PATH TO FILE  ${B}>>${D} " ; read input
targets="$input" ; else
echo -e -n "\n${B}Target > ${G2} AS number${D} - e.g. ${B}AS${D}36459 ${B}>> AS${D}" ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list" ; fi ; out="$outdir/ASNs.txt"
for asnum in $(cat "$targets") ; do
if [ $option_as1 = "1" ] || [ $option_as1 = "3" ] ; then
f_AS_SUMMARY "${asnum}" ; fi 
if [ $option_as1 = "3" ] ; then
f_Long ; echo "ANNOUNCED PREFIXES" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' ; fi
if [ $option_as1 = "2" ] || [ $option_as1 = "3" ] ; then
if [ $option_as1 = "2" ] ; then
f_asHEADER | tee -a ${out} ; fi
f_bgpPREFIXES ; fi ; done | tee -a ${out} ; else
echo -e -n "\n\n${B}Target > ${D} AS number -e.g. ${B}AS${D}36459 ${B}>> AS${D}" ; read asnum
out="${outdir}/AS.${asnum}.txt"
if [ $option_as = "2" ] ; then
f_asINFO | tee -a ${out} ; fi
if [ $option_as = "3" ] ; then
f_BGPviewPREFIXES | tee -a ${out} ; fi
if [ $option_as = "5" ] ; then
f_AS_ROUTING_Cons "${asnum}" | tee -a ${out} ; fi
if [ $option_as = "4" ] ; then
f_PEERING | tee -a ${out} ; fi ; fi ; fi
echo '' ; f_removeDir ; f_Menu
;;
#************** BLOCKLISTS / IP REPUTATION CHECKS *******************
bl|rep|reputation|blocklist|blocklists|blacklists|spam)
f_makeNewDir ; f_Long ; touch $tempdir/targets.list ; domain_enum="false"
echo -e "\n${B}Options > Target Types\n"
echo -e "${B} [1]${D} IPv4 Address(es)" ; echo -e "${B} [2]${D} IPv4 Network(s)"
echo -e -n "\n${B}  ?${D}   "  ; read option_type
if [ $option_type = "1" ] ; then
echo -e -n "\n${B}Option >${D} Show brief IP summary (geolocation/abuse contacts,AS,prefix) ${B} [y] | [n] ? ${D} " ; read option_summary ; fi
echo -e -n "\n${B}Target  > [1]${D}  Set Target ${B}| [2]${D}  Target List  ${B}?${D}  " ; read option_target
if [ $option_target = "1" ] ; then
echo -e -n "\n${B}Target  > ${G2}TARGET ${B}>>${D}  " ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list"
elif [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target  > ${G2}PATH TO FILE ${D}- e.g. ./hosts.list  ${B}>>${D} " ; read input
targets="$input" ; fi
if [ $option_type = "1" ] ; then
blocklists="$blocklists_host"; target_type="web"; target_type="other"; out="${outdir}/BLcheck.HOSTS.txt"; echo '' | tee -a ${out}
f_Long | tee -a ${out}; echo "IP REPUTATION" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' | tee -a ${out}; echo -e "Date:  $(date)\n" | tee -a ${out}
elif [ $option_type = "2" ] ; then
blocklists="$blocklists_net"; target_type="net"; out="${outdir}/NET_bl_check.txt"; echo '' | tee - ${out}; f_Long | tee -a  ${out}
echo "[+] NETWORK HOSTS BLOCKLIST CHECK | $(date)" ; f_Long | tee -a  ${out}
echo -e "\nChecking ...\n" | tee -a ${out}; echo -e "$blocklists_net" | sed '$!s/$/,/' | sed '1,1d' | tr '[:space:]' ' ' | fmt -s -w 80 | tee -a ${out}
echo -e "\n\nfor listed hosts from\n\n" | tee -a  ${out} ; cat $targets | tee -a ${out} ; fi
for x in $(cat $targets) ; do
if [ $option_type = "2" ] ; then
f_Long >> ${out}; echo -e "\n* $x" >> ${out} ; echo '' > $tempdir/listings
${PATH_ipcalc} -b -n ${x} 255.255.255.255 | grep -s 'Hostroute:' | cut -d ':' -f 2- | tr -d ' ' |
grep -E -v "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.0$" | grep -E -v "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.255$" > $tempdir/check.list
f_blocklistCHECK "$tempdir/check.list"
if [ -f $tempdir/listings ] ; then
cat $tempdir/listings >> ${out} ; else
echo -e "\nNo listed IP addresses found\n" >> ${out} ; fi ; fi
if [ $option_type = "1" ] ; then
if [ $option_summary = "y" ] ; then
f_Long | tee -a ${out} ; echo "$x" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' | tee -a ${out}
f_hostSHORT "${x}" | tee -a ${out} ; else
echo -e "\n________________________________________________\n" | tee -a ${out}; echo "  $x" ; fi
f_HOST_BL_CHECK "${x}" | tee -a ${out} ; fi ; done
echo '' ; f_removeDir ; f_Menu
;;
#************** DOMAIN RECON *******************
d|dom|domain|domains|recon|subs|subdomains)
f_makeNewDir; f_Long; domain_enum="true" ; option_source="1"; page_details="true"; ssl_details="false";
blocklists="$blocklists_domain" ; option_detail="1" ; declare -a ns_array=(); target_type="web"; rep_check="false"
option_testSSL="2"; option_sslscan="0"; option_vhosts="true"
option_starttls="1"; option_dns_details="n" ; option_ttl="1"
echo -e -n "\n${B}Target  > ${G2}DOMAIN  ${B}>>${D}  " ; read x
echo -e -n "\n${B}Option  > ${G2}whois ${B}>${D} Look up whois info for network ranges ${B}[y] | [n] ?${D}  " ; read option_whois
if  [ $option_connect = "0" ] ; then
echo -e "\n${B}Options >${G2} Subdomains\n" ; echo -e "${B} [1]${D} Subdomains (IPv4)"
echo -e "${R} [0]${D} SKIP" ; echo -e -n "\n${B}  ?${D}  "  ; read option_subs
echo -e "\n${B}Options  >${G2} MX, NS\n"
echo -e "${B} [1]${D} Check SPAM Blocklists" ; echo -e "${B} [2]${D} Check for unauthorized zonetransfers"
echo -e "${B} [3]${D} BOTH" ; echo -e "${R} [0]${D} SKIP" ; echo -e -n "\n${B}  ? ${D}  " ; read option_zone ; else
echo -e "\n${B}Option > ${G2}curl ${B}> ${G2} User Agent ${B}>\n"
echo -e "${B} [1]${D} default" ; echo -e "${B} [2]${D} $ua_moz" ; echo -e -n "\n${B}  ? ${D}  " ; read option_ua
if [ $option_ua = "2" ] ; then
curl_ua="-A $ua_moz" ; else
curl_ua="" ; fi
echo -e "\n${B}Option  > ${G2}WhatWeb\n"
echo -e "${B} [1]${D} Get Whatweb results via hackertarget.com"
echo -e "${R} [0]${D} SKIP" ; echo -e -n "\n${B}  ? ${D}  " ; read option_api
if [ $option_api = "1" ] ; then
ww="true" ; else
ww="false"; fi
echo -e "\n${B}Options > ${G2}Subdomains\n"
echo -e "${B} [1]${D} Subdomains (IPv4)" ; echo -e "${B} [2]${D} Subdomains (IPv4, IPv6)"
echo -e "${R} [0]${D} SKIP" ; echo -e -n "\n${B}  ?${D}  "  ; read option_subs
echo -e "\n${B}Name Servers (System Defaults)${D}\n" ; f_systemDNS
echo -e "\n\n${B}Options > ${G2}Name Servers ${B}>\n"; echo -e "${B} [1]${D} Use system defaults"; echo -e "${B} [2]${D} 9.9.9.9"
echo -e "${B} [3]${D} 1.1.1.1"; echo -e "${B} [4]${D} Set custom NS"; echo -e -n "\n${B}  ? ${D}  "; read option_ns
if [ $option_ns = "2" ] ; then
dig_array+=(@9.9.9.9); nssrv="@9.9.9.9"
elif [ $option_ns = "3" ] ; then
dig_array+=(@1.1.1.1) ;  nssrv="@1.1.1.1"
elif [ $option_ns = "4" ] ; then
echo -e -n "\n${B}Set     >${D} NAME SERVER  ${B} >>${D}   " ; read ns_input
dig_array+=(@ns_input); nssrv="@${ns_input}" ; else
nssrv="" ; fi
echo -e "\n${B}Options >${G2} DNS RECORDS\n"
echo -e "${B} [1]${D} Check Threat Feeds & DNS Blocklists" ; echo -e "${B} [2]${D} Check for unauthorized zonetransfers"
echo -e "${B} [3]${D} BOTH" ; echo -e "${R} [0]${D} SKIP" ; echo -e -n "\n${B}  ? ${D}  " ; read option_zone
echo -e -n "\n${B}Option  > ${G2}Load Balancing Detection ${B}>${D} Run lbd  ${B}?  [y] | [n] ${D}  " ; read option_lbd ; fi
out="$outdir/${x}.txt" ; f_textfileBanner "${x}" >> ${out}; eff_url=''
if [ $option_connect = "0" ] ; then
curl -s https://api.hackertarget.com/whatweb/?q=${x}${api_key_ht} > $tempdir/ww.txt
target_type="dnsrec"; f_PAGE "${x}" | tee -a ${out} ; else
option_source="1"; dig_array+=(+noall +answer +noclass +ttlid); declare -a st_array=() ; st_array+=(-sLkv)
declare -a curl_array=() ; curl_array+=(-sLkv) ; error_code=6 ; curl -s -f -L -k ${x} > /dev/null
if [ $? = ${error_code} ]; then
echo -e "\n${R} $x WEBSITE CONNECTION: FAILURE${D}\n\n"
echo -e "\n $x WEBSITE CONNECTION: FAILURE\n" >> ${out}
option_connect="0" ; f_Long | tee -a ${out} ; f_whoisSTATUS "${x}" | tee -a ${out} ; f_Short | tee -a ${out}
f_DNS_REC "${x}" | tee -a ${out}; f_certINFO "${x}" | tee -a ${out}; option_connect="1" ; else
f_writeOUT "${x}" ; f_HEADERS "${x}" > ${outdir}/HEADERS.${x}.txt
if [ $ww = "true" ] ; then
curl -s https://api.hackertarget.com/whatweb/?q=${x}${api_key_ht} > $tempdir/ww.txt ; fi
eff_url=$(grep "^URL:" $tempdir/response | cut -d ':' -f 2- | sed 's/^ *//')
host $x > $tempdir/hostip; target4=$(grep "has address" $tempdir/hostip | awk '{print $NF}')
target6=$(grep "has IPv6 address" $tempdir/hostip | awk '{print $NF}')
echo "$target4" > $tempdir/ip4.list ; echo "$target6" > $tempdir/ip6.list
target_host=$(echo $eff_url | sed 's/http:\/\///' | sed 's/https:\/\///' | cut -d '/' -f 1)
if echo $eff_url | grep -q -E "\.edu\.|\.co\.|\.org.|\.gov\."; then
target_host_dom=$(echo $eff_url | sed 's/http:\/\///' | sed 's/https:\/\///' | cut -d '/' -f 1 | rev | cut -d '.' -f 1,2,3 | rev) ; else
target_host_dom=$(echo $eff_url | sed 's/http:\/\///' | sed 's/https:\/\///' | cut -d '/' -f 1 | rev | cut -d '.' -f 1,2 | rev) ; fi
if ! [ "$x" = "$target_host" ] ; then
target_host4=$(host -t a $target_host | grep -w -i "has address" | rev | cut -d ' ' -f 1 | rev | sort -V)
target_host6=$(host -t aaaa $target_host | grep -w -i "has IPv6 address" | rev | cut -d ' ' -f 1 | rev | sort -V)
echo "$target_host4" >> $tempdir/ip4.list ; echo "$target_host6" >> $tempdir/ip6.list ; fi
f_domainSTATUS "${x}" | tee -a ${out} ; cat $tempdir/domain_status > ${outdir}/WHOIS.${x}.txt ; echo '' | tee -a ${out}
for a in $(cat $tempdir/ip4.list | sort -uV) ; do
f_WEB "${a}"; echo '' ; f_BANNERS "${a}"; echo ''; done | tee -a ${out}
if [ -f $tempdir/ip6.list ] ; then
for z in $(cat $tempdir/ip6.list | sort -uV) ; do
f_WEB "${z}";  echo ''; done | tee -a ${out} ; fi
if [ $option_lbd = "y" ] ; then
f_LBD "${x}" | tee -a ${out}
if ! [ "$x" = "$target_host_dom" ] && ! [ "$target4" = "$target_host4" ] ; then
f_LBD "${target_host_dom}" | tee -a ${out} ; fi ; fi
f_PAGE "${x}" | tee -a ${out}
declare -a st_array=() ; st_array+=(-s4Lkv); target_type="web" ; target="${x}"
for a in $target4 ; do
f_getWHOIS "${a}"; f_WHOIS_OUT "${a}" >> $outdir/WHOIS.${x}.txt; f_serverINSTANCE "${a}" ;done | tee -a ${out}
if [ -n "$target6" ] ; then
declare -a st_array=() ; st_array+=(-sLkv)
for z in $target6 ; do
f_getWHOIS "${z}"; f_WHOIS_OUT "${z}" >> $outdir/WHOIS.${x}.txt; f_serverINSTANCE "${z}" ;done | tee -a ${out} ; fi
if ! [ "$target4" = "$target_host4" ] ; then
declare -a st_array=() ; st_array+=(-s4Lkv); target_type="web" ; target="${target_host}"
for a in $target_host4 ; do
f_getWHOIS "${a}"; f_WHOIS_OUT "${a}" >> $outdir/WHOIS.${x}.txt ; f_serverINSTANCE "${a}" ;done | tee -a ${out} ; fi
serial_domain=$(echo | timeout 3 openssl s_client -connect ${x}:443 2>/dev/null | openssl x509 -noout -nocert -serial)
serial_target_host=$(echo | timeout 3 openssl s_client -connect ${target_host}:443 2>/dev/null | openssl x509 -noout -nocert -serial)
f_certINFO "${x}" | tee -a ${out}
if ! [ "$serial_domain" = "$serial_target_host" ] ; then
f_certINFO "${target_host}" | tee -a ${out} ; fi
option_testSSL="0"; f_DNS_REC "${x}" | tee -a ${out}
if ! [ "$x" = "$target_host_dom" ] ; then
f_DNS_REC "${target_host_dom}" | tee -a ${out} ; fi
f_dnsREC_II "${x}" | tee -a ${out}
cat $tempdir/ip4.list >> $tempdir/ips.list
ttl="+ttlunits"; f_TTL_READABLE "${x}"
target_type="dnsrec" ; type_mx="true" ; f_DNSdetails | tee -a ${out} ; type_mx="false"
if [ $option_zone = "1" ] || [ $option_zone = "3" ] ; then
echo ''  | tee -a ${out}; f_Long | tee -a ${out}; echo "[+] DNS RECORDS | IP REPUTATION CHECK" | tee -a ${out}
f_Long | tee -a ${out}; echo -e "\nChecking ...\n" | tee -a ${out}
echo -e "$blocklists_domain" | sed '$!s/$/,/' | sed '1,1d' | tr '[:space:]' ' ' | fmt -s -w 90 | tee -a ${out}
echo -e "Project Honeypot, Stop Forum SPAM, Spamhaus ZEN, Grey Noise Community API & SANS Internet Storm Center\n" | tee -a ${out}
for i in $(cat $tempdir/ips.list | sort -uV); do
f_IP_REPUTATION "${i}" ; done | tee -a ${out}
if [ -f $tempdir/isc ] ; then
echo  -e "________________________________________________\n" | tee -a ${out}
echo -e "\nGetting results from SANS Internet Storm Center Threatfeeds for DNS Records...\n" | tee -a ${out}
cat $tempdir/isc | tee -a ${out} ; fi ; echo '' | tee -a ${out}; fi
if [ $option_zone = "2" ] || [ $option_zone = "3" ] ; then
f_AXFR "${x}" | tee -a ${out}
if ! [ "$x" = "$target_host_dom" ] ; then
f_AXFR "${target_host_dom}" | tee -a ${out} ; fi ; else
echo '' | tee -a ${out} ; fi
f_subs_HEADER "${x}" | tee -a ${out}
if [ $option_whois = "y" ] ; then
f_Long | tee -a ${out} ; echo -e "\nReminder:  Network names are not considered unique identifiers." | tee -a ${out}
echo -e "Watch out for false positives within the 'Resources for' sections.\n" | tee -a ${out}
cat $tempdir/domain_nets | tee -a ${out} ; fi
echo '' | tee -a ${out}; cat ${outdir}/LINK_DUMP.${x}.txt | tee -a ${out}; echo '' | tee -a ${out}
for i in $host4 ; do
f_VHOSTS "${i}" ; done | tee -a ${out}
cat ${outdir}/HEADERS.${x}.txt | tee -a ${out}
if [ -f ${outdir}/SUBDOMAINSall_v4.$x.txt ] ; then
cat ${outdir}/SUBDOMAINSall_v4.$x.txt | tee -a ${out} ; else
cat ${outdir}/Subdomains_HT.${x}.txt | tee -a ${out}; fi
if [ $option_subs = "2" ] ; then
cat ${outdir}/SUBS.v6.$x.txt | tee -a ${out} ; fi ; fi ; fi
echo '' ; f_removeDir ; f_Menu
;;
#************** DNS OPTIONS *******************
dns|mx|ns|zone|zonetransfer|dig|nslookup|nsec)
f_makeNewDir; f_Long; domain_enum="false"; type_net="false"; option_detail="1"; target_type="dnsrec"; blocklists="$blocklists_domain"
ssl_details="false" ; quiet_dump="false"; option_testSSL="0";  declare -a dig_array=() ; f_optionsDNS
echo -e -n "\n  ${B}?${D}  " ; read option_dns
if ! [ $option_dns = "b" ] ; then
#************** DOMAIN DNS RECORDS *******************
if [ $option_dns = "1" ] ; then
option_starttls="1"
echo -e -n "\n${B}Target  > [1]${D} Set target Domain ${B}| [2]${D} Target List  ${B}?${D}  " ; read option_target
if [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target  > ${G2}PATH TO FILE ${D}- e.g. ./domains.list ${B}>>${D}  " ; read input
hosts="${input}" ; else
echo -e -n "\n${B}Target  > ${G2}DOMAIN  ${B}>>${D}  " ; read input
echo "$input" > $tempdir/hosts.list ; hosts="$tempdir/hosts.list" ; fi
if [ $option_connect = "0" ] ; then
echo -e "\n${B}Options > ${G2} IP REPUTATION / SPAM BLOCKLIST CHECK\n"
echo -e "\n${B} [1]${D} Check Blocklists/Threat Intelligence APIs"
echo -e "${R} [0]${D} SKIP" ; echo -e -n "\n${B}  ? ${D}  " ; read option_records1
echo -e "\n${B}Options > ${G2}MX & NS${B}> ${D}\n"
echo -e "${B} [1]${D} Check for unauthorized zonetransfers"
echo -e "${R} [0]${D} SKIP" ; echo -e -n "\n${B}  ? ${D}  " ; read option_zone1 ; else
echo -e -n "\n${B}Option  >${D} Customize Enumeration Options  ${B}[y] | [n]  ?${D}  " ; read option_lookup
if [ $option_lookup = "n" ] ; then
option_ttl="3"; rfc1912="false" ; option_zone1="0"; option_sslscan="n"; dns_chain="false"; ptr_records="true"; option_records1="0"
rfc1912="false"; option_mx1="0" ; option_dnsgeo="n" ; option_bl="n"; option_dns_details="n"; dig_array+=(+noall +answer +noclass) ; else
option_dns_details="y"
echo -e "\n${B}Nameservers (System Defaults)${D}\n" ; f_systemDNS
echo -e "\n\n${B}Options > Settings > ${G2}Name Server\n"
echo -e "${B} [1]${D} Use system defaults" ; echo -e "${B} [2]${D} 9.9.9.9"
echo -e "${B} [3]${D} 1.1.1.1" ; echo -e "${B} [4]${D} Set custom NS" ; echo -e -n "\n${B}  ? ${D}  " ; read option_ns
if [ $option_ns = "2" ] ; then
dig_array+=(@9.9.9.9) ; nssrv="@9.9.9.9"
elif [ $option_ns = "3" ] ; then
dig_array+=(@1.1.1.1) ; nssrv="@1.1.1.1"
elif [ $option_ns = "4" ] ; then
echo -e -n "\n${B}Set     >${D} NAME SERVER  ${B} >>${D}   " ; read ns_input
dig_array+=(@nssrv) ; nssrv="@${ns_input}" ; else
nssrv="" ; fi ; dig_array+=(+noall +answer +noclass)
echo -e "\n${B}Options > ${G2} TTL\n"
echo -e "${B} [1]${D} TTL values (ms)" ; echo -e "${B} [2]${D} TTL values (human readable)"
echo -e "${B} [3]${D} BOTH" ; echo -e -n "\n${B}  ? ${D}  " ; read option_ttl
echo -e "\n${B}Options >${G2} IP REPUTATION / WHOIS & GEOLOCATION\n"
echo -e "${B} [1]${D} Check Blocklists/Threat Intelligence APIs"
echo -e "${B} [2]${D} Get geolocation & whois data for all records"
echo -e "${B} [3]${D} BOTH"; echo -e "${R} [0]${D} SKIP" ; echo -e -n "\n${B}  ? ${D}  " ; read option_records1
echo -e "\n${B}Options > ${G2} ZONE TRANSFER, DNS ZONE CONFIGS\n"
echo -e "${B} [1]${D} Check for unauthorized zone transfers"
echo -e "${B} [2]${D} Check zone configs for best practices (RFC 1912 et al.)"
echo -e "${B} [3]${D} BOTH" ; echo -e "${R} [0]${D} SKIP" ; echo -e -n "\n${B}  ? ${D}  " ; read option_zone1
if [ $option_zone1 = "2" ] || [ $option_zone1 = "3" ] ; then
rfc1912="true" ; else
rfc1912="false" ; fi
echo -e "\n${B}Options > ${G2} MX SSL CERTS\n"
echo -e "${B} [1]${D} MX SSL certificates - summary"
echo -e "${B} [2]${D} MX SSL certificates - details & SSL vulnerabilities"
echo -e "${R} [0]${D} SKIP" ; echo -e -n "\n${B}  ? ${D}  " ; read option_mx1
if [ $option_mx1 = "2" ] ; then
option_sslscan="3"; else
option_sslscan="0"; fi
if [ $option_records1 = "1" ] ; then
option_bl="y"
elif [ $option_records1 = "2" ] ; then
option_dnsgeo="y"
elif [ $option_records1 = "3" ] ; then
option_bl="y"; option_dnsgeo="y" ; else
option_bl="n"; option_dnsgeo="n" ; fi ; fi; fi
for x in $(cat $hosts) ; do
out="${outdir}/DNS.$x.txt"; f_DNS_REC "${x}" | tee -a ${out}; f_dnsREC_II "${x}" | tee -a ${out}
if ! [ $option_connect = "0" ] ; then
if [ $option_mx1 = "1" ] || [ $option_mx1 = "2" ] ; then
f_Long | tee -a ${out} ; echo "[+]  MX  |  SSL/TLS" | tee -a ${out}
mx_servers=$(awk '{print $NF}' $tempdir/mxservers.list | sed 's/.$//' | sort -uV); type_mx="true"
for m in $mx_servers ; do
f_certINFO "${m}"  ; done | tee -a ${out}; type_mx="false"; fi ; fi
if [ $option_zone1 = "1" ] || [ $option_zone1 = "3" ] ; then
echo ''  | tee -a ${out}; f_Long | tee -a ${out} ; echo -e "[+] $x | ZONE TRANSFER" | tee -a ${out} ; f_Long | tee -a ${out}
curl -s https://api.hackertarget.com/zonetransfer/?q=${x}${api_key_ht} > $tempdir/zone.txt
echo '' >> $tempdir/zone.txt ; cat $tempdir/zone.txt | tee -a ${out} ; fi
if ! [ $option_connect = "0" ] ; then
if [ $option_dnsgeo = "y" ] ; then
echo '' | tee -a ${out}
host_type="dnsrec" ; f_DNSdetails | tee -a ${out} ; host_type="default" ; fi ; fi
if [ $option_bl = "y" ] ; then
echo ''  | tee -a ${out}; f_Long | tee -a ${out}; echo "[+] DNS RECORDS | IP REPUTATION LOOKUP" | tee -a ${out}
f_Long | tee -a ${out}; echo -e "\nChecking ...\n" | tee -a ${out}
echo -e "$blocklists_domain" | sed '$!s/$/,/' | sed '1,1d' | tr '[:space:]' ' ' | fmt -s -w 90 | tee -a ${out}
echo -e "Project Honeypot, Stop Forum SPAM, Spamhaus ZEN, Grey Noise Community API" | tee -a ${out}
echo '' | tee -a ${out}
for i in $(cat $tempdir/rec_ips.list | sort -uV); do
f_IP_REPUTATION "${i}" ; echo  -e "________________________________________________\n" ; done | tee -a ${out}; fi
if ! [ $option_connect = "0" ] ; then
if ! [ $option_lookup = "n" ] ; then
f_Long | tee -a ${out}; echo '' | tee -a ${out}
dig ${nsserv} +noall +answer +showsearch +trace $x | fmt -s -w 120 | sed '/;; Received/{x;p;x;G}' | tee -a ${out}; fi ; fi ; done ; fi
#************** SHARED NAME SERVERS *******************
if [ $option_dns = "2" ] ; then
echo -e "\n${B}Shared DNS Server (Source: hackertarget.com)${D}\n"
echo -e -n "\n${B}Target >${G2} NAME SERVER ${B}>>${D}  " ; read targetNS ; echo ''
out="${outdir}/Domains_sharing_${targetNS}" ; echo '' | tee -a ${out}
f_Long | tee -a ${out}; echo -e "[+] SHARED NS | $targetNS" | tee -a ${out}
f_Long | tee -a ${out}; echo '' | tee -a ${out}
curl -s "https://api.hackertarget.com/findshareddns/?q=${targetNS}${api_key_ht}" > $tempdir/sharedns.txt
domain_count=$(cat $tempdir/sharedns.txt | wc -l)
if [[ $domain_count -lt 501 ]] ; then
dig +noall +answer +noclass +nottlid -f $tempdir/sharedns.txt | sed 's/A/,/' | sed '/NS/d' | sed '/CNAME/d' | tr -d ' ' | sed 's/,/\t/g' |
tee -a $tempdir/sharedns_hosts.txt ; cat $tempdir/sharedns_hosts.txt >> ${out}
sort -t . -k 1,1n -k 2,2n -k 3,3n -u >> $tempdir/ip.list ; echo '' | tee -a ${out}
f_Long | tee -a ${out}; echo "[+] pwhois Bulk Lookup" | tee -a ${out}; f_Long | tee -a ${out}
f_whoisTABLE "$tempdir/ip.list" ; cat $tempdir/whois_table.txt | cut -d '|' -f 1,2,3,4,5 | tee -a ${out} ; echo '' | tee -a ${out}
cut -d '|' -f 1 $tempdir/whois_table.txt | sed '/AS/d' | sed '/NA/d' | sed '/^$/d' | tr -d ' ' | sort -g -u  >> $tempdir/asnums.list
for a in $(cat $tempdir/asnums.list) ; do
asn=$(dig +short as$a.asn.cymru.com TXT | tr -d "\"" | sed 's/^ *//' | cut -d '|' -f 1,2,3,5); echo -e "\nAS $asn"; done | tee -a ${out}
echo '' | tee -a ${out} ; else
echo '' | tee -a ${out} ; cat $tempdir/sharedns.txt | tee -a ${out}; echo '' | tee -a ${out} ; fi ; fi
#************** ZONE TRANSFER / ZONE WALKING *******************
if [ $option_dns = "3" ] ; then
if [ $option_connect = "0" ] ; then
option_xfr="1" ; else
echo -e "\n${B}Options > ${G2}Zone Transfer / Zone Walk${B} > \n"
echo -e " ${B}[1]${G2} API          ${B}>${D}  stealthy, probes all NS records of the target domain"
echo -e " ${B}[2]${G2} dnsutils (dig) ${B}>${D} choose all or specific domain name servers"
echo -e "\n ${B}[3]${G2} NMAP         ${B}>${D} Zone Walk"
echo -e -n "\n${B}  ? ${D}  " ; read option_xfr ; fi
if [ $option_xfr = "3" ] ; then
echo -e -n "\n${B}Target >${G2} NAME SERVER ${B}>>${D}  " ; read target_ns
f_Long | tee -a ${out}; echo "[+] $target | ZONEWALK | NS: $target_ns | $(date)" | tee -a ${out} ; f_Long | tee -a ${out}
echo '' | tee -a ${out}
sudo ${PATH_nmap} -sSU -p 53 --script dns-nsec-enum --script-args dns-nsec-enum.domains=$target $target_ns | tee -a ${out}
elif [ $option_xfr = "2" ] ; then
echo -e -n "\n${B}Target >${G2} DOMAIN ${B}>>${D}  " ; read target
echo -e -n "\n${B}Server > [1]${D} All NS records ${B}| [2]${D} specific name server  ${B}?${D}  " ; read option_ns
if  [ $option_ns = "1" ] ; then
echo -e -n "\n${B}Target >${G2} NAME SERVER ${B}>>${D}  " ; read target_ns ; echo ''
f_Long | tee -a ${out}; echo "[+] $target | ZONE TRANSFER | $(date)" | tee -a ${out}; echo '' | tee -a ${out}
dig axfr @${target_ns} $target | tee -a $out ; else
dig ns +short $target | rev | cut -c  2- | rev > $tempdir/ns.txt
for i in $(cat $tempdir/ns.txt); do
dig axfr @${i} $target ; done | tee -a ${out} ; fi ; else
echo -e -n "\n${B}Target >${G2} DOMAIN ${B}>>${D}  " ; read target
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo "[+] $target | ZONE TRANSFER | $(date)" | tee -a ${out}; f_Long | tee -a ${out}
curl -s https://api.hackertarget.com/zonetransfer/?q=${x}${api_key_ht} > $tempdir/zone.txt
echo '' >> $tempdir/zone.txt ; cat $tempdir/zone.txt | tee -a ${out} ; fi ; fi
#************** MAIL SERVER SSL/TLS *******************
if [ $option_dns = "4" ] ; then
option_sslscan="3"; type_mx="true"
echo -e "\n${B}Options > \n"
echo -e "${B} [1]${D}  Domain MX Records - SSL Status & Ciphers"
echo -e "${B} [2]${D}  Mail Server (not domain-specific) - SSL Status & Ciphers"
echo -e -n "\n${B}  ?${D}   "  ; read option_type
if [ $option_type = "1" ] ; then
option_starttls="1"
echo -e -n "\n${B}Target  > ${G2}DOMAIN  ${B}>>${D}  " ; read x
f_MX "${x}" | tee -a ${out}; mxs=$(awk '{print $NF}' $tempdir/mxservers.list)
for a in $(cat $tempdir/mx_ipv4.list | sort -uV); do
ptr=$(host $a ${nsserv} | grep -E "name pointer" | rev | cut -d ' ' -f 1 | rev | tr '[:space:]' ' ')
if [ -n "$ptr" ] ; then
echo -e "$a \n     $ptr\n" ; else
echo -e "$a \n     no PTR record\n" ; fi ; done | tee -a ${out}
for m in $mxs ; do
f_certInfo "${m}" | tee -a ${out} ; done ; else
echo -e "\n${B}Options > ${G2} MX > STARTTLS \n"
echo -e "${B} [1]${D} SMTP" ; echo -e "${B} [2]${D} IMAP"
echo -e -n "\n${B}  ?${D}   "  ; read option_starttls
echo -e -n "\n${B}Target  > [1]${D}  Set Target ${B}| [2]${D}  Target List  ${B}?${D}  " ; read option_target
if [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target  > ${G2}PATH TO FILE ${D}- e.g. ./hosts.list  ${B}>>${D} " ; read input
targets="$input" ; else
echo -e -n "\n${B}Target  > ${G2}HOSTNAME/IP ADDRESS${B}>>${D}  " ; read input ; fi
echo "$input" > $tempdir/targets.list ; targets="$tempdir/hosts.list" ; fi
for x in $(cat $targets | sort -u); do
f_dnsFOR_CHAIN "${x}" | tee -a ${out}
f_certInfo "${x}" | tee -a ${out} ; done ; fi
#************** DIG BATCH MODE (DNS MASS LOOKUP) *******************
if [ $option_dns = "5" ] ; then
echo -e "\n${B}Options > dig >${D} Queries/ Record Types\n "
echo -e "${B} [1]${D} A" ; echo -e "${B} [2]${D} AAAA"
echo -e "${B} [3]${D} NS"
echo -e "${B} [4]${D} MX"
echo -e "${B} [5]${D} SRV"
echo -e "${B} [6]${D} ANY (input > Domain Names"
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
dig_array+=(ns) ; record="NS"
elif [ $option_record = "4" ] ; then
dig_array+=(mx) ; record="MX"
elif [ $option_record = "5" ] ; then
dig_array+=(srv) ; record="SRV"
elif [ $option_record = "6" ] ; then
dig_array+=(any) ; record="ANY" ; fi
dig_array+=(+noall +answer +noclass +nottlid)
f_Long | tee -a ${out} ; echo -e " [dig BATCH MODE] | RECORD TYPE: $record" | tee -a ${out}; f_Long | tee -a ${out}
dig ${dig_array[@]} -f ${input} | tee -a ${out} ; echo '' | tee -a ${out} ; fi ; fi
echo '' ; f_removeDir ; f_Menu
;;
#***************** REVERSE GOOGLE ANALYTICS SEARCH *****************
g|google|analytics)
f_makeNewDir ; f_Long
echo -e -n "${B}\nTarget > ${G2} Google Analytics ID ${B}>${D}  e.g. UA-123456 or pub-00123456789 ${B}>>${D}  " ; read gooid
out="$outdir/Rev_GoogleAnalytics.txt" ; f_Long | tee -a ${out}
echo -e " $gooid | REVERSE GOOGLE ANALYTICS LOOKUP" | tee -a  ${out} ; f_Long | tee -a ${out}
curl -s https://api.hackertarget.com/analyticslookup/?q=${gooid} | tee -a ${out}
echo -e "\nSource > hackertarget.com\n" | tee -a ${out} ; f_removeDir ; f_Menu
;;
#************** PUBLIC IP ADDRESS, NETWORK INTERFACES, DEFAULT ROUTES & NS *******************
i)
f_makeNewDir ; target_type="dns_rec"
out="${outdir}/LOCAL_SYSTEM.txt" ; f_Long | tee -a ${out}
pub4=$(curl -s -m 5 https://api.ipify.org?format=json | jq -r '.ip')
pub6=$(curl -s -m 5 https://api64.ipify.org?format=json | jq -r '.ip')
echo "[+] LOCAL SYSTEM SUMMARY | $(date)" | tee -a ${out} ; f_Long | tee -a ${out}
echo -e "\nUser:                $(whoami)" | tee -a ${out}
echo -e "\nGroups:              $(groups)" | tee -a ${out}
echo -e "\nMachine:             $(uname -n) | OS: $(uname -o), $(uname -r)\n" | tee -a ${out}
if ! [[ $(uname -o) =~ "Android" ]] ; then
echo '' | tee -a ${out} ; lspci | grep -E "Network|Ethernet" | cut -d ' ' -f 2- | sed 's/Network controller:/Network controller: /' |
sed '/Network controller:/G' | tee -a ${out} ; fi
echo -e "\n\nPublic IPv4:         $pub4" | tee -a ${out}
echo -e "\nPublic IPv6:         $pub6\n" | tee -a ${out}
f_Long  | tee -a ${out}; f_hostSHORT "${pub4}" | tee -a ${out}
echo '' | tee -a ${out}; f_IFLIST | tee -a ${out}
if ! [[ $(uname -o) =~ "Android" ]] ; then
f_Long | tee -a ${out}; echo -e "\n******************** DEFAULT DNS SERVERS *******************" | tee -a ${out}
f_systemDNS | tee -a ${out} ; fi
echo '' ; f_removeDir ; f_Menu
;;
#************** LOOK UP TARGET INFORMATION BY IP ADDRESS OR HOSTNAME *******************
ip|host)
f_makeNewDir ; f_Long ; touch $tempdir/targets.list ; domain_enum="false"; target_type="default"
blocklists="$blocklists_host" ; option_connect="0" ; option_source="2" ; option_authns="true"
echo -e "\n${B}Options > \n"
echo -e "${B} [1]${D} IPv4 Address" ; echo -e "${B} [2]${D} IPv6 Address"
echo -e "${B} [3]${D} Hostname" ; echo -e -n "\n${B}  ?${D}   "  ; read option_type ; f_Long
if [ $option_type = "3" ] ; then
f_optionsHOSTNAME
elif [ $option_type = "2" ] ; then
f_optionsHOSTSv6 ; else
f_optionsHOSTSv4 ; fi
echo -e -n "\n${B}  ?${D}   "  ; read option_enum1
if ! [ $option_enum1 = "b" ] ; then
if [ $option_enum1 = "3" ] && [ $option_type = "2" ] ; then
option_connect="1" ; else
option_connect="0" ; fi
if [ $option_enum1 = "1" ]; then
option_detail="1"; option_bl="n"; option_banners="false"; ww="false"
if [ $option_type = "3" ] ; then
target_type="other"; else
target_type="default"; fi
elif [ $option_enum1 = "3" ] ; then
if [ $option_type = "2" ] ; then
output="$out/ICMPv6.txt"
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
f_Long | tee -a ${out} ; echo -e "[+] ICMPv6 | $(date)" | tee -a ${out} ; f_Long | tee -a ${out} ; else
out="${outdir}/NPING.txt" ; echo '' | tee -a ${out}; f_Long | tee -a ${out} ; echo -e "[+] NPING (IMCP) | SOURCE: hackertarget.com | $(date)" ; fi
elif [ $option_enum1 = "2" ] ; then
if [ $option_type = "2" ] ; then
option_bl="n"; option_banners="false"; ww="false"; else
echo -e "\n${B}Options  > ${G2}Network Admin Contacts (Whois)\n"
echo -e "${B} [1]${D} Summary"
echo -e "${B} [2]${D} Details"
if [ $option_type = "3" ] ; then
echo -e "${R} [0]${D} SKIP"; fi
echo -e -n "\n${B}  ? ${D}  " ; read option_enum2
if [ $option_enum2 = "2" ] ; then
option_detail="2" ; else
option_detail="1"; fi
if [ $option_enum2 = "0" ] ; then
target_type="other"; fi
echo -e "\n${B}Options  > ${G2}Banners/IP Reputation\n"
echo -e "${B} [1]${D} Banner Grab"
echo -e "${B} [2]${D} IP Reputation Check"
echo -e "${B} [3]${D} BOTH" ; echo -e "${R} [0]${D} SKIP"
echo -e -n "\n${B}  ? ${D}  " ; read option_enum3
if [ $option_enum3 = "1" ] ; then
option_banners="true"
elif [ $option_enum3 = "2" ] ; then
option_bl="y" ; option_banners="false"
elif [ $option_enum3 = "3" ] ; then
option_bl="y"; option_banners="true"; else
option_bl="n"; option_banners="false"; fi
if [ $option_type = "3" ] ; then
echo -e "\n${B}Option  > ${G2}Certificates\n"
echo -e "${B} [1]${D} List target certificate issuances via certspotter API"
echo -e "${R} [0]${D} SKIP"
echo -e -n "\n${B}  ? ${D}  " ; read option_enum4
echo -e "\n${B}Option  > ${G2}WhatWeb${B}>\n"
echo -e "${B} [1]${D} Run Whatweb against target if Banner Grab identifies target as web server"
echo -e "${B} [2]${D} Try running WhatWeb even if Banner Grab doesn't return any results"
echo -e "${R} [0]${D} SKIP"
echo -e -n "\n${B}  ? ${D}  " ; read option_enum5
if ! [ $option_enum5 = "0" ] ; then
option_banners="true"; ww="true"; else
option_banners="false"; ww="false"; fi; fi; fi; fi
echo -e -n "\n${B}Target  > [1]${D}  Set Target ${B}| [2]${D}  Target List  ${B}?${D}  " ; read option_target
if [ $option_target = "1" ] ; then
if [ $option_type = "2" ] ; then
echo -e -n "\n${B}Target  > ${G2}IPv6 ADDRESS ${B}>>${D}  " ; read input ; else 
echo -e -n "\n${B}Target  > ${G2}IPv4 ADDRESS / HOSTNAME ${B}>>${D}  " ; read input ; fi 
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list"
elif [ $option_target = "2" ] ; then
if [ $option_type = "2" ] ; then
echo -e -n "\n${B}Target  > ${G2}PATH TO FILE ${D}- e.g. ./hosts.list, (expected: IPv6 Addresses, separated by new line)  ${B}>>${D} " ; read input ; else
echo -e -n "\n${B}Target  > ${G2}PATH TO FILE ${D}- e.g. ./hosts.list, (expected: either IPv4 Addresses or Hostnames, separated by new line)  ${B}>>${D} "
read input ; fi
targets="$input" ; fi
if [ $option_type = "3" ] ; then
for x in $(cat $targets | sort -uV) ; do
out="${outdir}/HOST_INFO.${x}.txt"
echo '' | tee -a ${out}; f_Long | tee -a ${out}
echo "[+]  $x" | tee -a ${out}; f_DNSWhois_STATUS "${x}" | tee -a ${out}
host_ips=$(jq -r '.data.forward_nodes' $tempdir/chain.json | sed '/\[/d' | egrep -s -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sort -uV)
for i in $host_ips ; do
f_TYPE_HOSTNAME "${i}"; done | tee -a ${out}
if [ $ww = "true" ] ; then
if [ -f $tempdir/http ] || [ $option_enum5 = "2" ] ; then
curl -s https://api.hackertarget.com/whatweb/?q=${x}${api_key_ht} > $tempdir/ww.txt
page_details="true"; f_PAGE "${x}" | tee -a ${out} ; rm $tempdir/http; fi ; fi
if ! [ $option_enum1 = "1" ] && ! [ $option_enum5 = "0" ] ; then
f_certINFO "${x}"; fi; done ; else
for x in $(cat $targets | sort -uV) ; do
if [ $option_type = "1" ] ; then
f_BOGON "${x}"
if [ $bogon = "TRUE" ] ; then
echo -e "\n${R}BOGON${D} Address detected; aborting...\n" ; else 
if [ $option_enum1 = "3" ] ; then
echo -e "\n* $x \n" | tee -a ${out}
curl -s https://api.hackertarget.com/nping/?q=${x}${api_key_ht}  | tee -a ${out}; echo '' | tee -a ${out}; else
out="${outdir}/HOST_INFO.${x}.txt" ; echo '' | tee -a ${out} 
if [ $option_enum1 = "4" ] ; then
f_VHOSTS "${x}" | tee -a ${out} ; else
f_hostDEFAULT "${x}" | tee -a ${out}; fi ; fi ; fi ; fi 
if [ $option_type = "2" ] ; then
if [ $option_enum1 = "3" ] ; then
echo -e "\n* $x\n" ; sudo ${PATH_thcping6} ${v6_array[@]} ${x} | sed '/packet sent/{x;p;x;G;}' | tee -a ${out} ; echo ' ' | tee -a ${out}
elif [ $option_enum1 = "1" ] || [ $option_enum1 = "2" ] ; then
out="${outdir}/HOST_INFO.${x}.txt" ; echo '' | tee -a ${out}; f_hostDEFAULT "${x}" | tee -a ${out}; else
echo -e "\nExpected input: IPv4 Address !\n" ; fi ; fi ; done ; fi ; fi 
if [ $option_connect = "0" ] ; then
echo '' ; f_Long ; f_targetCONNECT ; fi
echo '' ; f_removeDir ; f_Menu
;;
#************** INTERNET EXCHANGE INFORMATION *******************
ix|ixid)
f_makeNewDir; echo ''; f_Long ; echo -e -n "\nTarget > ${D} IX ID - e.g. 25  ${B}>>${D}  " ; read ixid
out="${outdir}/IX.${ixid}.txt" ; curl -s "https://api.bgpview.io/ix/$ixid" > $tempdir/ix.json
f_Long | tee -a ${out}; echo -e " IX | IX-$ixid | $(jq -r '.data.name' $tempdir/ix.json)" | tee -a ${out}
f_Long | tee -a ${out} ; echo '' | tee -a ${out}
jq -r '.data | .name_full, .city, .country_code, .tech_email, .tech_phone, .website' $tempdir/ix.json | tee -a ${out}
echo -e "\nMembers:  $(jq -r '.data.members_count' $tempdir/ix.json)" | tee -a ${out}
echo -e -n "\nList all members  [y] [n]  ? " ; read option_members
if [ $option_members = "y" ] ; then
f_Short | tee -a ${out}; echo "[+] Members" | tee -a ${out};  jq -r '.data.members[]' $tempdir/ix.json | tr -d '{,\"}' |
sed 's/^ *//' | tee -a ${out} ; fi  ; echo '' ; f_removeDir ; f_Menu
;;
l|lan)
f_makeNewDir ; out="${outdir}/LOCAL_NETWORKS.txt"
f_Long | tee -a ${out}; echo -e "[+] LOCAL NETWORKS | $(date)" | tee -a ${out}; f_Long | tee -a ${out}; echo '' | tee -a ${out}
nmap --iflist > $tempdir/iflist; sed '/Starting Nmap/d' $tempdir/iflist | sed '/INTERFACES/G' | sed '/ROUTES/{x;p;x;G}'
f_Long; f_optionsLAN ; echo -e -n "\n  ${B}?${D}  " ; read option_lan
if ! [ $option_lan = "b" ] ; then
if ! [ $option_lan = "5" ] ; then
echo ''; f_Long ; echo -e "\n${B}Settings > ${G2}Interface ${D}\n"
echo -e -n "Enter Network Interface Name or '0' to send Broadcasts from all available NICs (the latter only works for IPv4 Options) ${B} >> ${D}  "
read nic
if ! [ $nic = "0" ] ; then
iface="-e $nic" ; iface6="$nic" ; else
iface='' ; iface6='' ; fi ; fi
if [ $option_lan = "1" ] ; then
out="${outdir}/BROADCASTS.ARP.txt"
echo -e -n "\n${B}Target  > ${G2}Network (CIDR)  ${B}>>${D}  " ; read target
echo '' | tee -a ${out} ; f_Long | tee -a ${out} ; echo -e "Interface: $nic"; echo -e "Network: $target"
echo -e "\n\nARP Broadcast\n_____________\n\n" | tee -a ${out}
sudo nmap ${iface} -R -sP $target > $tempdir/arp
grep -E "Nmap scan report|Host is|rDNS|MAC Address:" $tempdir/arp  | sed '/scan report/i \_______________________________________________\n' |
sed '/Nmap scan report for/G' | sed 's/Nmap scan report for/*/g' | sed '/Host is up/G' | sed 's/Host is/  Host is/g' |
sed 's/MAC Address:/  MAC Addr: /g' | tee -a ${out}; echo '' | tee -a ${out}
elif [ $option_lan = "2" ] ; then
out="${outdir}/BROADCASTS.DHCP.txt"
sudo ${PATH_nmap} --script broadcast-dhcp-discover 2>/dev/null > $tempdir/dhcp_discover
grep '|' $tempdir/dhcp_discover | tr -d '|_' | sed 's/^ *//' | sed '/Interface:/{x;p;x;}' | sed '/Subnet Mask/G' |
sed '/Message Type:/G' | sed '/NTP Servers:/G' | sed 's/broadcast-dhcp-discover:/\n\nDHCP Discover\n_____________\n/g' | tee -a ${out}
elif [ $option_lan = "3" ] ; then
out="${outdir}/BROADCASTS.RIP2.txt"
sudo ${PATH_nmap} --script broadcast-rip-discover 2> /dev/null | sed 's/broadcast-rip-discover:/\nRIP2 Discover\n_____________\n\n' | tee -a ${out}
elif [ $option_lan = "4" ] ; then
out="${outdir}/BROADCASTS.OSPF2.txt"
sudo ${PATH_nmap} -e ${if} --script=broadcast-ospf2-discover 2> /dev/null | tr -d '|_' | sed 's/^ *//' |
sed 's/ospf2-discover/\nOSPF Discover\n______________\n\n/' | sed '/External Routes/{x;p;x;}' | tee -a ${out}
elif [ $option_lan = "6" ] ; then
out="${outdir}/ATK6.ROUTER_DHCP6.txt"
sudo ${PATH_dump_router6} wlp3s0 ${if} | sed 's/^ *//' | sed '/Router:/{x;p;x;G}' | sed '/Options:/{x;p;x;G}' | sed '/MAC:/{x;p;x;}' | tee -a ${out}
echo -e "\n" | tee -a ${out}
sudo ${PATH_dump_dhcp6} -N ${if} | tee -a ${out}
elif [ $option_lan = "5" ] ; then
echo -e -n "\n${B}Target  > ${G2}Network (CIDR)  ${B}>>${D}  " ; read target
target_id=$(echo $target | cut -d '/' -f 1)
out="${outdir}/NMAP_LAN.$target_id.txt"
declare -a nmap_array=()  ; declare -a port_array=()
nmap_array+=(-sV -sS -sU)
echo -e -n "\n${B}Set   > ${D}Name for Nmap Output Files  ${B}>>${D}  " ; read filename
echo -e "\n${B}Options > ${G2}Nmap ${B}>\n"
echo -e "${B} [1]${D} Version Scan (Network- & SCADA- Services)" ; echo -e "${B} [2]${D} Version & Operating System Scan (slower)"
echo -e "${B} [3]${D} Version, OS & Vulnerablility (CVEs, unprotected access to FTP services & mySQL/MS-SQL root accounts)"
echo -e -n "\n${B}  ? ${D}  " ; read option_nmap
echo -e "\n\n${B}Target Ports  >\n"
echo -e "${B} [1]${D}\n"
echo "$ports_lan" | fmt -s -w 60
echo -e "\n${B} [2]${D}\n\nCustom Port List"
echo -e -n "\n${B}  ?${D}  " ; read portChoice
if   [ $portChoice = "1" ] ; then
port_array+=(-p ${ports_lan}) ; else
echo -e -n "\n${B}Ports  > ${D} e.g. 636,989-995  ${B}>>${D}  " ; read ports
port_array+=(-p ${ports}) ; fi
if [ $option_nmap = "2" ] ; then
scripts="$nse_lan,$nse_lan_os" ; script_args='' ; nmap_array+=(-O)
elif [ $option_nmap = "3" ] ; then
scripts="$nse_lan,$nse_lan_os,$nse_lan_vulners"
script_args="--script-args http-methods.test-all" ; nmap_array+=(-O) ; else
scripts="$nse_lan"; script_args='' ; fi
sudo ${PATH_nmap} ${nmap_array[@]} --open ${port_array[@]} ${target} > $tempdir/nmap.txt
echo '' | tee -a ${out}
f_Long | tee -a ${out}
echo "[+] NMAP | $target | $(date)" | tee -a ${out}
grep -E "Nmap scan report|Host is|Not shown|PORT|\||\|_|open|closed|MAC Address|Device type:|Running:|OS details|Nmap done:" $tempdir/nmap.txt | sed '/PORT/{x;p;x;G}' |
sed '/Nmap scan report/i \______________________________________________________________________________\n' | sed '/Nmap scan report/G' | sed '/CVE/i \__\n' |
sed '/Nmap done:/i \______________________________________________________________________________\n' | sed '/Nmap done:/G' | sed 's/Nmap scan report for/*/g' |
sed '/\/tcp/i \----------------------------------------------------------\n' | sed '/\/udp/i \----------------------------------------------------------\n' |
sed 's/Host is/  Host is/g' | sed 's/Not shown:/  Not shown:/g' | sed '/MAC Address:/i \----------------------------------------------------------\n' |
sed 's/Running:/Running:    /g' | sed 's/OS details:/\nOS details:  /g' | tee -a ${out}
fi ; fi ; echo '' ; f_removeDir ; f_Menu
;;
#************** NETWORK OPTIONS *******************
n|net|nets|networks|prefix|prefixes|pfx|banners|pingsweep|rdns)
f_makeNewDir ; f_Long ; target_type="net" ; domain_enum="false"; net_ip=$(echo $s | cut -d '/' -f 1)
echo -e "\n${B}Options > ${G2}Type ${B}>\n"
echo -e "${B} [1]${D} IPv4 Network(s)" ; echo -e "${B} [2]${D} IPv6 Network(s)"
echo -e -n "\n${B}  ?${D}   "  ; read option_type ; f_optionsNET ; echo -e -n "\n${B}  ?${D}  " ; read option_enum
if ! [ $option_enum = "b" ] ; then
if [ $option_enum = "1" ] ; then
set_output="false"; option_detail="1"
elif [ $option_enum =  "2" ] ; then
echo -e "\n${B}Options > ${G2}WHOIS CONTACTS\n"; echo -e "${B} [1]${D} Whois Contact Details"
echo -e "${B} [2]${D} Org & admin-c Summary"; echo -e -n "\n${B}  ? ${D}  " ; read option_custom
if [ $option_custom = "1" ] ; then
option_netdetails1="3"; option_detail="2"; else
option_netdetails1="2"; option_detail="3"; fi
set_output="false"; option_netdetails2="3"; option_netdetails3="1"; option_netdetails4="1"; dns_servers='' ; option_source="1"
elif [ $option_enum =  "3" ] ; then
set_output="false"
echo -e "\n${B}Options > ${G2}DETAILS I\n" ; echo -e "${B} [1]${D} Network Contact Details"
echo -e "${B} [2]${D} Related networks, geographic distribution, assignments"
echo -e "${B} [3]${D} BOTH" ; echo -e "${R} [0]${D} SKIP" ; echo -e -n "\n${B}  ? ${D}  " ; read option_netdetails1
if [ $option_netdetails1 = "1" ] || [ $option_netdetails1 = "3" ] ; then
option_detail="2" ; else
option_detail="3" ; fi
echo -e "\n${B}Options > ${G2}DETAILS II${B} Whois-Address Space Consistency / Rev. DNS Lookup Zones\n"
echo -e "${B} [1]${D} Show subnets & Address Space Details"; echo -e "${B} [2]${D} List Rev. DNS Lookup Zones (RIPE only)"
echo -e "${B} [3]${D} BOTH" ; echo -e "${R} [0]${D} SKIP"; echo -e -n "\n${B}  ? ${D}  " ; read option_netdetails2
if ! [[ ${net_ip} =~ $REGEX_IP4 ]] ; then
option_netdetails3="0"; option_netdetails4="0" ; else
echo -e "\n${B}Options >\n"; echo -e "${G2} [1]${D} Proceed with current options"
echo -e "${B} [2]${D} Show more options"; echo -e -n "\n${B}  ? ${D}  " ; read choice
if [ $choice = "1" ] ; then
option_ip6="n"; f_OPTIONSnetRDNS ; echo -e -n "\n${B}  ? ${D}  " ; read option_netdetails3
echo -e "\n${B}Options > IPv4 Nets > ${G2}Service Banners${B} > \n"; echo -e "${B} [1] ${G2}API${B}  >${D}  hackertarget.com IP API"
echo -e "${R} [0]${D} SKIP"; echo -e -n "\n${B}  ?${D}  " ; read option_netdetails4
if [ $option_netdetails3 = "3" ] ; then
option_source="3"
elif [ $option_netdetails3 = "2" ] ; then
option_source="2"; echo -e -n "\n${B}Set     >${D} Name Server(s) - e.g. ns1.example.com,ns2.example.com  ${B} >>${D}   " ; read input
nssrv=$(echo $input | tr -d ' '); dns_servers="--dns-servers $nssrv" ; else
dns_servers='' ; option_source="1" ; fi ; fi ; fi 
elif [ $option_enum = "4" ] ; then
set_output="true"
elif [ $option_enum = "5" ] ; then
set_output="true"
if [ $option_type = "2" ] && ! [ $option_connect = "0" ] ; then
echo -e -n "\n${B}Target > ${D}IPv6 NETWORK ${B}|${D} REVERSE DOMAIN ADDRESS  ${B}>>${D}  " ; read target
f_Short ; f_DELEGATION "${target}"
echo -e -n "\n\n${B}Target > ${D}NAME SERVER ${B}>>${D}  " ; read target_ns
echo -e -n "\n${B}Option > [1] ${D} UDP  ${B} | [2] ${D} TCP  ${B}?${D}  " ; read input_protocol
if [ $input_protocol = "2" ] ; then
protocol="-t" ; else
protocol="" ; fi ; fi
if [ $option_type = "1" ] ; then
if [ $option_connect = "0" ] ; then
option_source="3" ; else
f_OPTIONSnetRDNS
echo -e -n "\n${B}  ?${D}  " ; read option_source
if [ $option_source = "2" ] ; then
echo -e -n "\n${B}Set     >${D} Name Server(s) - e.g. ns1.example.com,ns2.example.com  ${B} >>${D}   " ; read input
nssrv=$(echo $input | tr -d ' ')
dns_servers="--dns-servers $nssrv" ; else
dns_servers='' ; fi
echo -e -n "\n${B}Option  >${D} Look up ${B}IPv6 Addresses${D} for IPv4 PTR records? ${B} [y] | [n]  ?${D}  " ; read option_ip6; fi ; fi
elif [ $option_enum = "6" ] ; then
set_output="false"
elif [ $option_enum = "8" ] ; then
set_output="false"
elif [ $option_enum = "7" ] ; then
set_output="false"
if [ $option_connect = "0" ] ; then
option_source="1" ; else
echo -e "\n${B}Options > IPv4 Nets > ${G2}Service Banners${B}\n"
echo -e "${B} [1] ${G2}API${B}  >${D}  hackertarget.com IP API"
echo -e "${B} [2] ${G2}NMAP${B} >${D}  Version Scan & Host Discovery (Ping Sweep)"
echo -e "${B} [3] ${G2}NMAP${B} >${D}  Version Scan, NO Ping"
echo -e -n "\n${B}  ?${D}  " ; read option_source
if ! [ $option_source = "1" ] ; then
declare -a nmap_array=()  ; declare -a port_array=() ; scripts="$nse_net"
nmap_array+=(-sV -sUV --open)
if [ $option_source = "3" ] ; then
nmap_array+=(-Pn) ; fi
echo -e "\n\n${B}Options > ${G2}Target Ports\n"
echo -e "${B} [1]${D}"
echo "$nmap_top15" | fmt -s -w 60
echo -e "${B} [2]${D}\nCustom Port List"
echo -e -n "\n${B}  ?${D}  " ; read portChoice
if   [ $portChoice = "1" ] ; then
port_array+=(-p ${nmap_top15}) ; else
echo -e -n "\n${B}Ports   > ${D} e.g. 636,989-995  ${B}>>${D}  " ; read ports
port_array+=(-p ${ports}) ; fi; fi ; fi ; fi
if [ $option_enum = "8" ] ; then
set_output="false" ; echo -e -n "\n${B}Option  > ${D}Run Nmap with root priviliges ${B}[y] | [n]  ?${D}  " ; read option_root
declare -a psweep_array=() ; echo -e "\n${B}Options > ${G2}PING SWEEP\n"
echo -e "${B} [1]${D} Use Nmap Defaults"
echo -e "${B} [2]${D} Customize host discovery options"
echo -e -n "\n${B}  ? ${D}  " ; read option_pingsweep
if [ $option_pingsweep = "2" ] ; then
if [ $option_root = "y" ] ; then
echo -e "\n${B}Options > ${G2}PING${B} > PROTOCOLS${B} > ${G2}ICMP\n"
echo -e "${B} [1]${D} ICMP ECHO" ; echo -e "${B} [2]${D} ICMP TIMESTAMP"
echo -e "${B} [3]${D} BOTH" ; echo -e "${R} [0]${D} SKIP"
echo -e -n "\n${B}  ? ${D}  " ; read option_icmp
if ! [ $option_icmp = "0" ] ; then
if [ $option_icmp = "1" ] ; then
psweep_array+=(-PE)
elif [ $option_icmp = "2" ] ; then
psweep_array+=(-PP) ; else
psweep_array+=(-PE -PP) ; fi; fi ; fi
echo -e "\n${B}Options > ${G2}PING${B} > PROTOCOLS${B} > ${G2}TCP\n"
echo -e "${B} [1]${D} TCP SYN" ; echo -e "${B} [2]${D} TCP ACK"
echo -e "${B} [3]${D} BOTH" ; echo -e "${R} [0]${D} SKIP"
echo -e -n "\n${B}  ? ${D}  " ; read option_tcp
if ! [ $option_tcp = "0" ] ; then
if [ $option_tcp = "3" ] ; then
echo -e -n "\n${B}Ports   > ${G2} TCP SYN ${B}> - e.g. 25,80,135  ${B}>>${D} " ; read target_ports
psweep_array+=(-PS${target_ports})
echo -e -n "\n${B}Ports   > ${G2} TCP ACK ${B}> - e.g. 25,80,135  ${B}>>${D} " ; read target_ports
psweep_array+=(-PS${target_ports}) ; else
echo -e -n "\n${B}Ports   > ${D}- e.g. 25,80,135  ${B}>>${D} " ; read target_ports ; fi
if [ $option_tcp = "1" ] ; then
psweep_array+=(-PS${target_ports}) ; else
psweep_array+=(-PA${target_ports}) ; fi ; fi ; fi
if [ $option_root = "y" ] ; then
echo -e "\n${B}Options > ${G2}PING${B} > PROTOCOLS${B} > ${G2}SCT & UDP\n"
echo -e "${B} [1]${D} SCT (Socket Connect)" ; echo -e "${B} [2]${D} UDP"
echo -e "${B} [3]${D} BOTH" ; echo -e "${R} [0]${D} SKIP"
echo -e -n "\n${B}  ? ${D}  " ; read option_udp
if ! [ $option_udp = "0" ] ; then
if [ $option_udp = "3" ] ; then
echo -e -n "\n${B}Ports   > ${G2} SCT ${B}> - e.g. 25,80,135  ${B}>>${D} " ; read target_ports
psweep_array+=(-PY${target_ports})
echo -e -n "\n${B}Ports   > ${G2} UDP ${B}> - e.g. 25,80,135  ${B}>>${D} " ; read target_ports
psweep_array+=(-PU${target_ports}) ; else
echo -e -n "\n${B}Ports   > ${D}- e.g. 25,80,135  ${B}>>${D} " ; read target_ports ; fi
if [ $option_udp = "1" ] ; then
psweep_array+=(-PY${target_ports}) ; else
psweep_array+=(-PU${target_ports}) ; fi ; fi ; fi ; fi
echo -e -n "\n${G2}Target${B}  > [1]${D} Single target network ${B}| [2]${D} Target list ${B}?${D}  " ; read option_target
if [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target  > ${G2}PATH TO FILE  ${B}>>${D}   " ; read input
nets="${input}" ; else
echo -e -n "\n${B}Target  > ${G2}Network (CIDR)  ${B}>>${D}   " ; read input
echo "$input" > $tempdir/nets.list ; nets="$tempdir/nets.list" ; fi
if [ $report = "true" ] && [ $set_output = "true" ] ; then
echo -e -n "\n${B}Option > ${D}Set Custom Name for Output File ${B}[y] | [n]  ?${D}  " ; read option_filename
if [ $option_filename = "y" ] ; then
echo -e -n "\n${B}Set    > ${D}OUTPUT - FILE NAME ${B}>>${D}  " ; read filename
out="${outdir}/$filename.txt" ; else
out="$out" ; fi ; fi
if [ $option_enum = "4" ] ; then
if [ $option_filename = "n" ] ; then
out="${outdir}/ADDR_SPACE_ENUM.txt" ; fi
echo '' | tee -a ${out}; f_Long | tee -a ${out}
echo -e "[+] PREFIX ADDRESS SPACE / SUBNET SEARCH | $(date)" | tee -a ${out}
f_Long | tee -a ${out}
echo -e -n "\n${B}Options > ${D}Filter results ${B}[y] | [n]  ?${D}  " ; read option_filter
if [ $option_filter = "y" ] ; then
echo -e -n "\n${B}Filter  > ${D}Single Searchterm or csv - e.g. access,backbone,service  ${B}>>${D}  " ; read filter
echo "$filter" | tr -d ' ' | sed 's/,/\n/g' | tr -d ' ' > $tempdir/filters ; fi
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo -e "[+] PREFIX ADDRESS SPACE" | tee -a ${out}; f_Long | tee -a ${out}
echo -e "\nSearching for ...\n" | tee -a ${out} ; cat $tempdir/filters | tee -a ${out}
echo -e "\nwithin\n" | tee -a ${out} ; cat $nets | tee -a ${out}
for x in $(cat "$nets") ; do
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo -e "[+] $x | ADDRESS SPACE" | tee -a ${out}; f_Long | tee -a ${out}
f_addressSPACE "${x}" | tee -a ${out} ; done ; else
if [ $option_enum = "4" ] &&  [ $option_filename = "y" ]  ; then
echo '' | tee -a ${out}; f_Long | tee -a ${out} ; echo "[+] NETWORK REVERSE DNS" | tee -a ${out} ; f_Long | tee -a ${out}
echo -e "\nTarget Networks:\n" | tee -a ${out}
cat $nets | tee -a ${out} ; fi
for x in $(cat $nets) ; do
net_ip=$(echo $x | cut -d '/' -f 1)
if [ $option_enum = "1" ] ; then
option_detail="1"; option_netdetails1="0"; option_netdetails2="0"; option_netdetails3="0"; option_netdetails4="0"
out="${outdir}/NETWORKS.txt" ; f_whoisNET "${x}" | tee -a ${out} ; fi
if [ $option_enum = "3" ] ; then
out="${outdir}/NET_ENUM.${net_ip}.txt"; f_whoisNET "${x}" | tee -a ${out}; fi
if [ $option_enum = "2" ] ; then
out="${outdir}/NET_REPORT_FULL.${net_ip}.txt"; f_whoisNET "${x}" | tee -a ${out}
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo -e "DATE:    $(date)\n" | tee -a ${out}
echo -e "SOURCES: DNS lookup, hackertarget.com IP API, RIPEstat Data API, whois.ripe.net\n" | tee -a ${out}
echo -e "         port scanning: false\n" | tee -a ${out} ; fi
if [ $option_enum = "5" ] ; then
if [ $option_filename = "n" ] ; then
out="${outdir}/REV_DNS.${net_ip}.txt" ; fi
if [ $option_type = "2" ] && [ $option_connect = "0" ] ; then
f_Long | tee -a ${out}; echo "$address | REVERSE DNS" | tee -a ${out}; f_Long | tee -a ${out}; echo '' | tee -a ${out}
sudo ${PATH_rdns6} ${protocol} ${target_ns} ${target} | tee -a ${out} ; else
f_NET_HEADER "${x}" | tee -a ${out}
if [ $option_connect = "0" ] ; then
option_ip6="n" ; fi
f_NETrDNS "${x}" | tee -a ${out}; fi; fi
if [ $option_enum = "6" ] ; then
out="${outdir}/VHOSTS.${net_ip}.txt"
f_NET_HEADER "${x}" | tee -a ${out}; echo -e "*\n $x VHosts\n" | tee -a ${out}; f_RevIP "${x}" | tee -a ${out} ; fi
if [ $option_enum = "7" ] ; then
out="${outdir}/BANNERS.${net_ip}.txt" ; f_NET_HEADER "${x}" | tee -a ${out}
if [ $option_source = "1" ]  ; then
f_BANNERS "${x}" | tee -a ${out} ; else
echo '' | tee -a ${out}
sudo ${PATH_nmap} ${nmap_array[@]} -oA ${out}/${filename} ${port_array[@]} ${scripts} ${target} > $tempdir/nmap.txt
f_NMAP_OUT | tee -a ${out} ; fi ; fi
if [ $option_enum = "8" ] ; then
out="${outdir}/PINGSWEEP.${net_ip}.txt"
f_NET_HEADER "${x}" | tee -a ${out}
echo -e "\n* $x  PING SWEEP" | tee -a ${out}
if [ $option_root = "y" ] ; then
sudo ${PATH_nmap} ${x} -sn ${psweep_array[@]} -oA ${out} > $tempdir/pingsweep.txt ; else
${PATH_nmap} ${x} -sn -R ${psweep_array[@]} -oA ${out} > $tempdir/pingsweep.txt ; fi
grep -E "Nmap scan report|Host is|rDNS" $tempdir/pingsweep.txt  | sed '/scan report/i \_______________________________________________\n' |
sed 's/Nmap scan report for/*/g' | sed 's/Host is/  Host is/g' | tee -a ${out} ; fi
done ; fi ; fi
echo '' ; f_removeDir ; f_Menu
;;
p|ports|portscan|nmap) echo '' ; f_Long; f_options_P ;;
t|trace|traceroute|rpki|mtu) echo '' ; f_Long; f_options_T ;;
#************** WEB SERVER OPTIONS *******************
web|webserver|webservers|website|ssl|tls|www)
f_makeNewDir; f_Long; domain_enum="false"; option_detail="1"; blocklists="$blocklists_host" ; target_type="web"; option_authns="0"
option_source="1" ; error_code=6
f_optionsWWW; echo -e -n "\n${B}  ?${D}  "  ; read option_www
if ! [ $option_www = "b" ] ; then
if [ $option_www = "3" ] ; then
rep_check="false" ; else
rep_check="true" ; fi
echo -e "\n${B}Option > ${G2}curl ${B}> ${G2} User Agent\n"
echo -e "${B} [1]${D} default" ; echo -e "${B} [2]${D} $ua_moz" ; echo -e -n "\n${B}  ? ${D}  " ; read option_ua
if [ $option_ua = "2" ] ; then
curl_ua="-A $ua_moz" ; else
curl_ua="" ; fi
if ! [ $option_www = "2" ] ; then
option_enum1="0"; option_enum2="0"; option_enum3="0"; else
f_Long; echo -e "${B} Options 1/3 > ${G2} Connectivity, Server Response\n"
echo -e "${B} [1]${D} Check connection reliability / SSL performance /server response- & page loading times\n"
echo -e "${R} [0]${D} SKIP"
echo -e -n "\n${B}  ?${D}  " ; read option_enum1
if [ $option_enum1 = "1" ] ; then
option_ping="y" ; request_times="1" ; option_sslscan="1"
echo -e -n "\n${B}Option  > ${D}Do you have superuser/root priviliges ${B}[y] | [n]  ?${D}  " ; read option_root
echo -e "\n${B}Options > ${G2} TRACEROUTE\n"
echo -e "${B} [1]${D} Tracepath" ; echo -e "${B} [2]${D} MTR (via API)"
if [ $option_root = "y" ] ; then
echo -e "${B} [3]${D} MTR (local inst.)"; fi
echo -e "${R} [0]${D} SKIP"; echo -e -n "\n${B}  ?${D}  " ; read option_trace; else
option_ping="n"; request_times="0" ; option_trace="n" ; fi
f_Long; echo -e "\n${B} Options 2/3 > ${G2} SSL-Configurations & SSL-Security\n"
echo -e "${B} [1]${D} Check SSL implementation / test for common SSL vulnerabilities\n"
echo -e "${R} [0]${D} SKIP" ; echo -e -n "\n${B}  ?${D}  "; read option_enum2
f_Long; echo -e "${B} Options 3/3 > ${G2} Website / Server Vulnerability Scan\n"
echo -e "${B} [1]${D} Safe Mode - Run Vulnerability Scans using Nmap Script from category 'safe' only"
echo -e "${B} [2]${D} Intrusive Mode - FAST (using 'safe' & 'intrusive' skripts, while skipping some time consuming script scans)"
echo -e "${B} [3]${D} Intrusive Mode - ALL"
echo -e "${R} [0]${D} SKIP"
echo -e -n "\n${B}  ?${D}  " ; read option_enum3 ; fi
if [ $option_enum3 = "0" ] ; then
ww="false"; page_details="false" ; fi
if [ $option_enum2 = "1" ] ; then
ssl_details="true" ; option_testSSL="4"; option_sslscan="2" ; else
if [ $option_enum1 = "1" ] ; then
ssl_details="false"
if ! [ $option_enum3 = "0" ] || ! [ $option_enum2 = "0" ] ; then
option_sslscan="2"; fi; fi ; fi
if ! [ $option_enum3 = "0" ] ; then
echo -e -n "\n${B}Option  > ${D}Run Nmap with root priviliges ${B}[y] | [n]  ?${D}  " ; read option_root
if ! [ $option_enum2 = "1" ] ; then
if [ -n "$PATH_testssl" ] ; then
option_testSSL="3"; option_sslscan="0" ; else
option_sslscan="1"; fi; fi
page_details="true"; declare -a nmap_array=()
if [ $option_root = "y" ] ; then
nmap_array+=(-sV -O --osscan-limit -Pn -R --resolve-all --open)
if [ $option_enum3 = "2" ] ; then
scripts="$nse_basic,$nse_web_safe,$nse_web1,vulners"; script_args="--script-args http-methods.test-all"
elif [ $option_enum3 = "3" ] ; then
scripts="$nse_basic,$nse_web_safe,$nse_web1,$nse_web2,vulners"; script_args="--script-args http-methods.test-all" ; else
scripts="$nse_basic,$nse_web_safe,vulners" script_args='' ; fi ; else
nmap_array+=(-sT -Pn -R --resolve-all --open)
if [ $option_enum3 = "2" ] ; then
scripts="$nse_basic,$nse_web_safe,$nse_web1"; script_args="--script-args http-methods.test-all"
elif [ $option_enum3 = "3" ] ; then
scripts="$nse_basic,$nse_web_safe,$nse_web1,$nse_web2"; script_args="--script-args http-methods.test-all" ; else
scripts="$nse_basic,$nse_web_safe" script_args='' ; fi ; fi
echo -e "\n${B}Options > ${G2}Ports ${B}> \n"
echo -e "${B} [1]${D} $ports_web1" ; echo -e "${B} [2]${D} $ports_web2"
echo -e "${B} [3]${D} $ports_web3" ; echo -e "${B} [4]${D} $ports_web4"
echo -e "${B} [5]${D} customize ports" ; echo -e -n "\n${B}  ? ${D}  " ; read option_ports
if [ $option_ports = "1" ] ; then
p_array+=(${ports_web1})
elif [ $option_ports = "2" ] ; then
p_array+=(${ports_web2})
elif [ $option_ports = "3" ] ; then
p_array+=(${ports_web3})
elif [ $option_ports = "3" ] ; then
p_array+=(${ports_web4}) ; else
echo -e -n "\n${B}Set     > Ports  ${D}- e.g. 636,989-995  ${B}>>${D} " ; read add_ports
p_array+=(${add_ports}) ; fi
echo -e "\n${B}Options > ${G2}WFUZZ ${B}>\n"
echo -e "${B} [1]${D} Check robots.txt" ; echo -e "${B} [2]${D} Server Directories Bruteforcing"
echo -e "${B} [3]${D} BOTH" ; echo -e "${R} [0]${D} SKIP" ; echo -e -n "\n${B}  ? ${D}  " ; read option_wfuzz
echo -e -n "\n${B}Options >${D} WhatWeb ${B}> [1]${D} Local App ${B}| [2]${D} hackertarget.com API  ${B}| ${R}[0]${D} SKIP  ${B}?${D}  "
read ww_source
if [ $ww_source = "1" ] || [ $ww_source = "2" ] ; then
ww="true" ; else
ww="false" ; fi ; fi
echo -e -n "\n${B}Target  > [1]${D}  Set Target ${B}| [2]${D}  Target List  ${B}?${D}  " ; read option_target
if [ $option_target = "1" ] ; then
echo -e -n "\n${B}Target  > ${G2}HOSTNAME  ${B}>>${D}  " ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list" ; else
echo -e -n "\n${B}Target > ${G2}PATH TO FILE  ${B}>>${D} " ; read input
targets="${input}" ; fi
for x in $(cat "$targets") ; do
if [ $option_www = "1" ] ; then
ww="false"; ssl_details="false"; option_testSSL="1"; option_sslscan="1"; request_times="1"; page_details="false" ; option_ping="y";
option_trace="0" ; quiet_dump="false"; option_enum1="0" ; option_enum2="0"; option_enum3="0"; option_root="n";
out="${outdir}/WEBSERV_HealthCheck.${x}.txt"
elif [ $option_www = "2" ] ; then
rep_check="true"; out="${outdir}/WEBSERV.${x}.txt"
elif [ $option_www = "3" ] ; then
page_details="true"; ww="false"; rep_check="false"; out="${outdir}/WEBSITE.${x}.txt"; fi
declare -a st_array=() ; st_array+=(-sLkv); declare -a curl_array=() ; curl_array+=(-sLkv)
declare -a ping_array=(); ping_array+=(-c 3)
if [ $? = ${error_code} ]; then
echo -e "\n${R} $x WEBSITE CONNECTION: FAILURE${D}\n\n"
echo -e "\n $x WEBSITE CONNECTION: FAILURE\n" >> ${out} ; else
if [ $option_www = "5" ] ; then
quiet_dump="true" ; f_certINFO "${x}" ; quiet_dump="false"
elif [ $option_www = "4" ] ; then
curl -sILk --max-time 3 ${x} > $tempdir/headers; f_HEADERS "${x}" > ${outdir}/HEADERS.${x}.txt; else
f_writeOUT "${x}" ; f_HEADERS "${x}" > ${outdir}/HEADERS.${x}.txt; f_www_test_HEADER | tee -a ${out}
target4=$(host -t a $x | grep -w -i "has address" | rev | cut -d ' ' -f 1 | rev)
target6=$(host -t aaaa $x | grep -w -i "has IPv6 address" | rev | cut -d ' ' -f 1 | rev)
eff_url=$(grep 'URL:' $tempdir/response | rev | cut -d ' ' -f 1 | rev)
target_host=$(echo $eff_url | sed 's/http:\/\///' | sed 's/https:\/\///' | cut -d '/' -f 1)
if [ $ww = "true" ] ; then
if [ $ww_source = "1" ] ; then
${PATH_whatweb} --no-errors --color=never ${x} > $tempdir/ww.txt
elif [ $ww_source = "2" ] ; then
curl -s https://api.hackertarget.com/whatweb/?q=${x}${api_key_ht} > $tempdir/ww.txt ; fi ; fi
f_PAGE "${x}" | tee -a ${out}
if [ $option_www = "3" ] ; then
f_Long | tee -a ${out}; echo "HOST SUMMARY" | tee -a ${out}
for a in $target4; do
f_hostSHORT "${a}" ; done | tee -a ${out}
cat ${outdir}/LINK_DUMP.${x}.txt | tee -a ${out}
cat ${outdir}/HEADERS.${x}.txt | tee -a ${out}; else
if [ $request_times = "1" ] ; then
f_requestTIME "${x}" | tee -a ${out} ; fi
if ! [ $option_enum3 = "0" ] ; then
if [ $option_root = "y" ] ; then
sudo ${PATH_nmap} ${nmap_array[@]} -p ${p_array[@]} ${x} 2>/dev/null -oA ${outdir}/NMAP4.${x} --script ${scripts},vulners ${script_args} > $tempdir/nmap.txt
else
${PATH_nmap} ${nmap_array[@]} -p ${p_array[@]} ${x} 2>/dev/null -oA ${outdir}/NMAP4.${x} --script ${scripts} ${script_args} > $tempdir/nmap.txt ; fi
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo "NMAP SCAN" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' | tee -a ${out}
f_NMAP_OUT | sed '/Host is up/d' | tee -a ${out}; echo '' | tee -a ${out}
if [ -n "$target6" ] ; then
if [ $option_root = "y" ] ; then
sudo ${PATH_nmap} -6 ${nmap_array[@]} -p ${p_array[@]} ${x} 2>/dev/null -oA ${outdir}/NMAP4.${x} --script ${scripts},vulners ${script_args} > $tempdir/nmap.txt
else
${PATH_nmap} -6 ${nmap_array[@]} -p ${p_array[@]} ${x} 2>/dev/null -oA ${outdir}/NMAP4.${x} --script ${scripts} ${script_args} > $tempdir/nmap.txt ; fi
echo -e "\n" | tee -a ${out}; f_Long | tee -a ${out}; echo -e "[+] $x | NMAP SCAN" | tee -a ${out}
f_NMAP_OUT | sed '/Host is up/d' | tee -a ${out}; echo '' | tee -a ${out} ; fi ; fi
declare -a st_array=() ; st_array+=(-s4Lkv)
declare -a htping_array=(); htping_array+=(-c 3) ; target="$x"
if [ $option_trace = "3" ] ; then
declare -a mtr_array=() ; mtr_array+=(-4 --tcp -P 80 -c 4 -b) ; fi
for a in $target4 ; do
f_serverINSTANCE "${a}" ; done | tee -a ${out}
if [ -n "$target6" ] ; then
declare -a st_array=() ; st_array+=(-sLkv); htping_array+=(-6 -c 3)
if [ $option_trace = "3" ] ; then
declare -a mtr_array=() ; mtr_array+=(-6 --tcp -P 80 -c 4 -b) ; fi
for z in $target6 ; do
declare -a htping_array=(); htping_array+=(-6 -c 3)
f_serverINSTANCE "${z}" ; done | tee -a ${out} ; fi
f_certINFO "${x}" | tee -a ${out}
if ! [ $option_enum3 = "0" ] ; then
if [ $option_wfuzz = "1" ] || [ $option_wfuzz = "3" ] ; then
if [ -n "$PATH_wfuzz" ] ; then
echo '' | tee -a ${out} ; f_Long | tee -a ${out} ; echo -e "[+] $target_host | robots.txt [WFUZZ] " | tee -a ${out} ; f_Long | tee -a ${out}
echo '' | tee -a ${out} ; ${PATH_wfuzz} --script=robots -z list,robots.txt -f $tempdir/fuzz $target_host/FUZZ ; echo ''
cat $tempdir/fuzz >> ${out} ; rm $tempdir/fuzz ; else
echo "Please install WFUZZ"; fi; fi
if [ $option_wfuzz = "2" ] || [ $option_wfuzz = "3" ] ; then
if [ -n "$PATH_wfuzz" ] ; then
echo '' | tee -a ${out} ; f_Long | tee -a ${out} ; echo -e "[+] $target_host | SERVER DIRECTORIES | [WFUZZ]" | tee -a ${out} ; f_Long | tee -a ${out}
wfuzz -w ${wordl_wfuzz1} --hc 404,403 -f $tempdir/fuzz $target_host/FUZZ ; echo ''
cat $tempdir/fuzz >> ${out} ; rm $tempdir/fuzz ; else
echo "Please install WFUZZ"; fi; fi
f_htmlCOMMENTS "${x}" | tee -a ${out}
if ! [ "$x" = "$target_host" ] ; then
f_htmlCOMMENTS "${target_host}" | tee -a ${out} ; fi
cat $tempdir/LINKS.${x}.txt | tee -a ${out} ; fi
if [ $option_enum2 = "1" ] ; then
echo '' | tee -a ${out}
cat $tempdir/writeout.${target}.txt | tee -a ${out} ; fi ; fi; fi ; fi ; done ; fi
echo '' ; f_removeDir ; f_Menu
;;
1)
#************** AFRINIC, APNIC & RIPE INVERSE & REVERSE SEARCHES (NETWORKS, ORGANISATIONS, CONTACTS) *******************
f_makeNewDir ; f_Long ; target_type="other" ; out="$tempdir/out11.txt" ; option_detail="1"; domain_enum="false"
echo -e "\n${B}Options > Sources > whois Servers >\n"
echo -e "${B} [1]${D}  RIPE" ; echo -e "${B} [2]${D}  AFRINIC"
echo -e "${B} [3]${D}  APNIC" ; echo -e -n "\n${B}   ?${D}  " ; read reg_choice
if [ $reg_choice = "2" ] ; then
rir="afrinic"; iregistry="AFRINIC" ; regserver="whois.afrinic.net"
elif [ $reg_choice = "3" ] ; then
rir="apnic"; iregistry="APNIC" ; regserver="whois.apnic.net" ; else
rir="ripe"; iregistry="RIPE" ; regserver="whois.ripe.net" ; fi
f_Long ; echo -e "${B}File Input${D} - one entry per line\n"
echo -e "${B}Regular Lookups${D} - name of object"
echo -e "\n${B}Inverse Lookups${D} - to activste inverse searches use the following syntax:\n"
echo -e "${G2}ObjectType;SearchTerm${D}  -  e.g.  admin-c;JohnDoeXY-RIPE"
echo -e "\nRegular & inverse Lookups can becombined in file input"; f_Long
echo -e -n "\n${B}Target  > [1]${D} Set target ${B}| [2]${D} Read from file  ${B}?${D}  " ; read option_target
if [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target  > ${D}PATH TO FILE  ${B}>>${D}   " ; read input
targets="${input}" ; else
echo -e -n "\n${B}Target  > ${D}SEARCH TERM  ${B}>>${D} " ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list" ; fi
if [ $option_target = "2" ] && [ $report = "true" ] ; then
echo -e -n "\n${B}Set   > ${D}OUTPUT - FILE NAME  ${B}>>${D}  " ; read filename ; fi
headl="$tempdir/headline"
echo -e "\n${R}Warning: ${D} Exzessive searches for non-abuse contact details are considered abusive."
echo -e "\n${B}Options > ${G2}PoC Details\n"
echo -e "${B} [1]${D} Do not Search for Personal Data"
echo -e "${B} [2]${D} Look up Full Contact Details"
echo -e "${B} [3]${D} Retrieve contact details once for every object, but do not search for personal data during inverse Lookups"
echo -e -n "\n${B}   ?${D}  " ; read option_poc
echo '' > ${headl}; f_Long | tee -a ${headl}; echo -e "WHOIS | OBJECT & INVERSE SEARCHES  [$regserver]" | tee -a ${headl}
f_Long | tee -a ${headl}; echo -e "\nSearching...\n" | tee -a ${headl} ; cat $targets | tee -a ${headl}
for x in $(cat $targets) ; do
if  [[ ${x} =~ ";" ]] ; then
iSearch="true" ; query_type=$(echo "$x" | cut -d ';' -f 1) ; obj=$(echo "$x" | cut -d ';' -f 2)
if [ $query_type = "org" ] ; then
echo "$obj" | tr -d ' ' >> $tempdir/orgs.list ; fi
if [ $option_target = "1" ] ; then
filename=$(echo $x | cut -d ';' -f 2- | tr -d ' ') ; fi ; else
iSearch="false"
if [ $option_target = "1" ] ; then
filename=$(echo $x | cut -d '/' -f 1 | tr -d ' ') ; fi ; fi
if [ $iSearch = "true" ] ; then
if [ $option_poc = "2" ] ; then
whois -h ${regserver} -- "-B -i ${query_type} ${obj}"  >> $tempdir/whois_temp ; else
whois -h ${regserver} -- "--no-personal -F -i ${query_type} ${obj}" | tr -d '*' | sed 's/^ *//' >> $tempdir/whois_temp ; fi
f_whoisFORMAT >> $tempdir/who1.txt ; fi
if [ $iSearch = "false" ] ; then
if [ $option_poc = "2" ] ; then
whois -h ${regserver} -- "-B ${x}" >> $tempdir/whois_temp ; else
whois -h ${regserver} -- "--no-personal -F ${x}"  | tr -d '*' | sed 's/^ *//' >> $tempdir/whois_temp ; fi
f_whoisFORMAT >> $tempdir/who1.txt ; fi ; done
if [ $iSearch = "true" ] ; then
if [ $option_poc = "3" ] ; then
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
netnames=$(grep -E -i "^netname:|^na:|^net-name:" $tempdir/full_output.txt | cut -d ':' -f 2- | sed 's/^ *//' | sort -uV)
asns=$(grep -E "^aut-num:|^an:|^origin:|^or:" $tempdir/full_output.txt | cut -d ':' -f 2- | sed 's/^ *//' | sort -ufV)
orgs=$(grep -s -E "^organisation:|^org:|^oa:|^og:"  $tempdir/full_output.txt | cut -d ':' -f 2- | sed 's/^ *//' | sort -uV)
if [ -n "$asns" ] || [ -n "$orgs2" ]; then
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo -e "[+] AUTONOMOUS SYSTEMS & ORGANISATIONS" | tee -a ${out}
f_Long | tee -a ${out} ; fi
if [ -n "$asns" ] ; then
echo -e "\n* ASNs\n" | tee -a ${out}; echo "$asns" | sed 's/AS/AS /g' | tee -a ${out} ; fi
if [ -n "$orgs" ] ; then
echo -e "\n* ORGs\n" | tee -a ${out} ; echo -e "$orgs\n" | tee -a ${out}; echo "$orgs" >> $tempdir/orgs.list ;  fi
if [ -n "$asns" ] ; then
for a in $(echo "$asns" | sed 's/AS//g') ; do
f_AS_SUMMARY "${a}" ; done | tee -a ${out} ; fi
if [ -n "$orgs" ] ; then
for oid in $(cat $tempdir/orgs.list | sort -u -V) ; do
whois -h ${regserver} -- "--no-personal $oid" > $tempdir/whois_org
echo ''; f_ORG "$tempdir/whois_org" ; done | tee -a ${out}
for oid in $(cat $tempdir/orgs.list | sort -u -V) ; do
echo '' ; f_netBLOCKS "${oid}" ; done | tee -a ${out} ; fi
echo '' | tee -a ${out} ; f_Long | tee -a ${out} ; echo -e "[+] NETWORKS & ROUTES" | tee -a ${out}; f_Long | tee -a ${out}
if [[ $(grep -s -E -c "^inet6num:|^i6:" $tempdir/full_output.txt ) -gt "0" ]] ; then
echo -e "* Network Ranges (IPv6)" | tee -a ${out}
grep -s -E -A 5 "^inet6num:|^i6:" $tempdir/full_output.txt > $tempdir/i6nums1
grep -E "^inet6num:|^i6:" $tempdir/i6nums1 | cut -d ' ' -f 2- | tr -d ' ' | sort -u -V > $tempdir/i6nums2
for i in $(cat $tempdir/i6nums2 | sort -u -V) ; do
grep -s -A 5 -m 1 ${i} $tempdir/i6nums1 | grep -s -E "^inet6num:|^netname:|^country:|^org-name:|^descr:|^i6:|^na:|^cy:|^og:|^de:" |
sed '/^i6:/i \_____________________________________\n' | sed '/inet6num/i \_____________________________________\n' |
cut -d ' ' -f 2- | sed 's/^ *//' ; done | tee -a ${out} ; fi
if [[ $(grep -s -E -c "^inetnum:|^in:" $tempdir/full_output.txt ) -gt "0" ]] ; then
echo -e "\n_____________________________________\n" | tee -a ${out} ; echo -e "* Network Ranges (IPv4)" | tee -a ${out}
grep -s -E -A 2 '^inetnum:|^in:' $tempdir/full_output.txt > $tempdir/inetnums1
grep -s -E '^inetnum:|^in:' $tempdir/inetnums1  | cut -d ':' -f 2- | tr -d ' ' | cut -d '-' -f 1 > $tempdir/inetnums2
sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n -u $tempdir/inetnums2 > $tempdir/inetnums_u4
grep -s -w '^inetnum:|^in:' $tempdir/inetnums1  | cut -d ':' -f 2- | tr -d ' ' | cut -d '-' -f 2 >> $tempdir/inetnums2
sort -t . -k 1,1n -k 2,2n -k 3,3n -u $tempdir/inetnums2 > $tempdir/inetnums_u3
for a in $(cat $tempdir/inetnums_u4) ; do
grep -s -m 1 -A 2 "${a}" $tempdir/inetnums1 >> $tempdir/netranges.txt
nrange=$(grep -s -m 1 "${a}" $tempdir/inetnums1 | cut -d ':' -f 2- | tr -d ' ')
ipcalc ${nrange} | sed '/deaggregate/d' | tail -1 >> $tempdir/cidr ; done
cat $tempdir/netranges.txt | sed '/inetnum/i \_____________________________________\n' |
sed '/^in:/i \_____________________________________\n' | cut -d ':' -f 2- | sed 's/^ *//' | tee -a ${out}
rm $tempdir/netranges.txt; echo '' | tee -a ${out}
if [[ $(cat $tempdir/cidr | wc -w) -gt 2 ]]; then
echo -e "\n_______________________________________\n"  | tee -a ${out}
cat $tempdir/cidr | tr -d ' '  | sort -t / -k 2,2n | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n -u -V | tr '[:space:]' ' ' | fmt -s -w 40 |
sed 's/ /  /g' | sed 's/^ *//' | tee -a ${out} ; else
echo ''; f_Shortest | tee -a ${out}; cat $tempdir/cidr | tr -d ' '  | sort -t / -k 2,2n | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n -u -V | tee -a ${out}; fi ; fi
if [ $option_poc = "1" ] ; then
route_obj4=$(sed -e '/./{H;$!d;}' -e 'x;/rt:/!d' $tempdir/full_output.txt | grep -E "^rt:|^or" | grep -E -B 1 "^or:" | sed '/--/d' | sed '/^$/d')
route_obj6=$(sed -e '/./{H;$!d;}' -e 'x;/r6:/!d' $tempdir/full_output.txt | grep -E "^r6:|^or" | grep -E -B 1 "^or:" | sed '/--/d' | sed '/^$/d'); else
route_obj4=$(sed -e '/./{H;$!d;}' -e 'x;/route:/!d' $tempdir/full_output.txt | grep -E "^route:|^origin" |
grep -E -B 1 "^origin:" | sed '/--/d' | sed '/^$/d')
route_obj6=$(sed -e '/./{H;$!d;}' -e 'x;/route6:/!d' $tempdir/full_output.txt | grep -E "^route6:|^origin" | grep -E -B 1 "^origin:" |
sed '/--/d' | sed '/^$/d') ; fi
if [ -n "$route_obj4" ] ; then
echo -e "\n_____________________________________\n" | tee -a ${out}; echo -e "* Routes (IPv4)" | tee -a ${out}
echo -e "_____________________________________" | tee -a ${out}; echo "$route_obj4" | sed 's/as/AS/g' > $tempdir/route_obj4
origin4=$(grep -E "^or:|^origin:" $tempdir/route_obj4 | cut -d ':' -f 2- | sed 's/^ *//' |  tr -d ' ' | sort -u -f -V)
for o in $origin4 ; do
echo -e "\n\n$o\n" | sed 's/AS/AS /g'; grep -E -B 1 "${o}" $tempdir/route_obj4 | sed '/--/d' | sed '/^$/d' | grep -E -v "^or:" | cut -d ' ' -f 2- |
sed 's/^ *//' | tr -d ' ' | sort -u -V | tee $tempdir/routes.$o.txt >> $tempdir/routes4
cat $tempdir/routes4 | tr -d ' '  | sort -t / -k 2,2n | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n -u -V
rm $tempdir/routes4 ; done | tee -a ${out} ; fi
if [ -n "$route_obj6" ] ; then
echo -e "\n_____________________________________\n" | tee -a ${out}; echo -e "* Routes (IPv6)" | tee -a ${out}
echo -e "_____________________________________" | tee -a ${out}; echo "$route_obj6" | sed 's/as/AS/g' > $tempdir/route_obj6
origin6=$(grep -E "^or:|^origin:" $tempdir/route_obj6 | cut -d ':' -f 2- | sed 's/^ *//' |  tr -d ' ' | sort -u -f -V)
for i in $origin6 ; do
echo -e "\n\n$i\n" | sed 's/AS/AS /g'
grep -E -B 1 "${i}" $tempdir/route_obj6 | sed '/--/d' | sed '/^$/d' | grep -E -v "^or:" | cut -d ' ' -f 2- |
sed 's/^ *//' | tr -d ' ' | sort -u -V | tee $tempdir/routes6.$i.txt ; done | tee -a ${out} ; fi
if [ $option_poc = "1" ] ; then
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo -e "[+] ABUSE CONTACTS & ADMIN-C" | tee -a ${out}; f_Long | tee -a ${out}
echo -e "* Abuse Contacts\n" | tee -a ${out}
cat $tempdir/full_output.txt | grep -s -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" | sort -u | tee -a ${out} ; else
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo -e "[+] POINTS OF CONTACT" | tee -a ${out}; f_Long | tee -a ${out}; echo '' | tee -a ${out}
grep -s -E "^role:|^person:" $tempdir/full_output.txt | cut -d ':' -f 2- | sed 's/^ *//' | sort -u | tee -a ${out}; echo '' | tee -a ${out}
grep -s "^nic-hdl:" $tempdir/full_output.txt | cut -d ':' -f 2- | sed 's/^ *//' | sort -u
echo '' | tee -a ${out}; grep -s -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/full_output.txt | sort -u | tee -a ${out}; fi
echo -e "\n\n* $iregistry Admin Handles\n" | tee -a ${out}
grep -s -E "^admin-c:|^ac:" $tempdir/full_output.txt  | sed 's/ac:/admin-c:/g' | tr ':' ';' | tr -d ' ' > $tempdir/handles.txt
sort -u $tempdir/handles.txt | tee -a ${out}
if [ $option_poc = "1" ] ; then
echo '' | tee -a ${out} ; admins=$(cut -d ';' -f 2 $tempdir/handles.txt | sed 's/^ *//' | tr -d ' ' | sort -uV)
for ac in $admins ; do
f_Long; f_ADMIN_C "${ac}" ; done | tee -a ${out} ; fi
nameservers=$(grep -E "^ns:|^nserver:" $tempdir/who1.txt | cut -d ':' -f 2- | sed 's/^ *//' | sort -uV)
if [ -n "$nameservers" ] ; then
echo '' | tee -a ${out}; f_Long | tee -a ${out} ; echo "[+]  NAME SERVERS  [SOURCE: WHOIS REVERSE DNS DELEGATIONS]" | tee -a ${out}
for ns in $nameservers ; do
f_Long; echo -e "$ns\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; f_hostSHORT "${ns}" ; done | tee -a ${out} ; fi
mail_contacts=$(grep -s -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/full_output.txt | sort -u)
if [ -n "$mail_contacts" ] ; then
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo "[+] Domains" | tee -a ${out}
for mc in $mail_contacts ; do
f_DNSWhois_STATUS "$(echo $mc | cut -d '@' -f 2)" ; done | tee -a ${out}; fi
if [ $iSearch = "true" ] ; then
if [ $option_poc = "3" ] ; then
echo -e "\n_________________________________________________________\n\n[+] Object Details" | tee -a ${out}
cat $tempdir/who2.txt | tee -a ${out} ; fi ; fi
if [ $option_poc = "2" ] ; then
cat $tempdir/who1.txt | sed 's/^ *//' | tr -d "\'" | sed '/organisation:/{x;p;x;}' | sed '/person:/{x;p;x;}' |
sed '/role:/{x;p;x;}' | sed '/route:/{x;p;x;}' | sed '/route6:/{x;p;x;}' | sed '/inetnum:/{x;p;x;}' | sed '/inet6num/{x;p;x;}' |
sed '/mntner/{x;p;x;}' | sed '/as-set/{x;p;x;}' | sed '/aut-num:/{x;p;x;}' | sed '/domain:/{x;p;x;}' | tee -a ${out} ; fi
cat $headl >> ${outdir}/WHOIS.${filename}.txt ; cat ${out} >> ${outdir}/WHOIS.${filename}.txt
cat $tempdir/who1.txt >> ${outdir}/WHOIS_full_out.txt ; echo '' ; f_removeDir ; f_Menu
;;
2)
#************** ARIN NETWORK, ORGANISATION & CONTACT SEARCH  *******************
f_makeNewDir ; f_Long ; option_detail="2" ; domain_enum="false" ; rir="arin"
echo -e "\n${B}File Input${D} - one entry per line\n"
echo -e "\n${B}Expected Input${D}\n"
echo -e "Organization ID or name, network names, abuse/NOC handles, \ndomain part of an e-mail address - e.g. @ibm.com from abuse@ibm.com\n"
f_Long; echo -e -n "\n${B}Target > [1]${D} Set target ${B}| [2]${D} Read from file  ${B}?${D}  " ; read option_target
if [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target  > ${G2}PATH TO FILE  ${B}>>${D}   " ; read input
targets="${input}" ; else
echo -e -n "\n${B}Target  > ${G2}SEARCH TERM  ${B}>>${D} " ; read input
echo "$input" > $tempdir/targets.list
targets="$tempdir/targets.list" ; fi
for x in $(cat $targets) ; do
f_arin_WHOIS "${x}" ; filename=$(echo $x | cut -d '/' -f 1)
out="$outdir/WHOIS_arin.$filename.txt"
if  [[ ${x} =~ "/" ]] ; then
target_type="net"; option_netdetails1="0"; option_netdetails2="0" ; option_netdetails3="0" ; option_netdetails4="0"
f_whoisNET "${x}" | tee -a ${out}
mail_domain=$(grep -E "^AbuseEmail|^OrgAbuseEmail:" $tempdir/whois | grep -E -m1 -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" | cut -d '@' -f 2)
orgid=$(grep -E "^OrgId:" $tempdir/whois | awk '{print $NF}' | head -1 | sed 's/^ *//' | tr -d ' '); f_DNSWhois_STATUS "${mail_domain}" | tee -a ${out}
elif  [[ ${x} =~ $REGEX_DOMAIN ]] || [[ ${x} =~ "@" ]] ; then
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo -e "[+]  $orgid | Networks  [source: whois.arin.net]" | tee -a ${out}; f_Long | tee -a ${out}
grep -s -E "^Name:|^Handle:|^Company:|^City:|^Country:|^Updated:|^Phone:|^Email:" $tempdir/whois |
sed 's/Name:/\n\nName:/' | tee -a ${out}
handle=$(grep -E "^Handle:" $tempdir/whois | head -1 | awk '{print $NF}' | sed 's/^ *//' | tr -d ' ')
orgid=$(whois -h whois.arin.net z $handle | grep -E "^OrgId:" | awk '{print $NF}' | sed 's/^ *//' | tr -d ' ') ; else
f_ARIN_ORG "$tempdir/whois" | tee -a ${out} ; orgid=$(grep -E "^OrgId:" $tempdir/whois | awk '{print $NF}' | head -1 | sed 's/^ *//' | tr -d ' ')
mail_domain=$(grep -E "^AbuseEmail|^OrgAbuseEmail:" $tempdir/whois | grep -E -m1 -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" | cut -d '@' -f 2)
f_DNSWhois_STATUS "${mail_domain}" | tee -a ${out} ; fi
net_name=$(grep -E "^NetName:" $tempdir/whois | head -1 | awk '{print $NF}' | sed 's/^ *//' | tr -d ' ')
f_netRESOURCES "${net_name}"
if [ -n "$orgid" ] ; then
if  [[ ${x} =~ $REGEX_DOMAIN ]] || [[ ${x} =~ "@" ]] ; then
whois -h whois.arin.net o $orgid > $tempdir/arin_org
f_Long | tee -a ${out}; echo "[+]  $orgid" | tee -a ${out}; f_ARIN_ORG "$tempdir/arin_org" | tee -a ${out}; fi
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo -e "[+]  $orgid | Networks  [source: whois.arin.net]" | tee -a ${out}; f_Long | tee -a ${out}
echo '' | tee -a ${out} ; whois -h whois.arin.net n $orgid | grep '('  | tee -a ${out} ; echo '' | tee -a ${out}
f_netBLOCKS "${orgid}" | tee -a ${out}; fi
if ! [[ ${x} =~ $REGEX_DOMAIN ]] || ! [[ ${x} =~ "@" ]] ; then
f_Long | tee -a ${out} ; echo -e "[+] $x Points of Contact" | tee -a ${out}; f_Long | tee -a ${out}; echo '' | tee -a ${out}
whois -h whois.arin.net -- "e + @$mail_domain" | grep -a -E "^Name:|^Handle:|^Company:|^City:|^Country:|^Updated:|^Phone:|^Email:" |
sed 's/Name:/\n\nName:/' | tee -a ${out} ; fi
done ; echo '' ; f_removeDir ; f_Menu
;;
3)
#************** pwhois.org NETBLOCK & ORGANISATION SEARCH *******************
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
echo -e -n "\n${B}Filter  > ${D}Country Code - e.g. de ${B}>>${D}  " ; read countrycode
filter=$(echo $countrycode | tr [:lower:] [:upper:] | cut -d ' ' -f 1 | tr -d '.,' | tr -d ' ') ; fi
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo "[+] Organisation- & Netblock- Search  [pwhois.org]" | tee -a ${out}
f_Long | tee -a ${out}
for oid in $(cat $targets) ; do
whois -h whois.pwhois.org "registry org-name=${oid}" > $tempdir/pwhois_org
if [ $option_filter = "y" ] ; then
cat $tempdir/pwhois_org | grep -s -E -i -w "^Org-ID:|^Org-Name:|^Country:|^Geo-Country:|^NOC-0-Handle:" | sed '/Org-ID/{x;p;x;}' |
cut -d ' ' -f 2- | sed 's/^ *//' | grep -E -w -B 2 -A 1 "^${filter}" | sed '/--/d' | tee $tempdir/orgs_filtred
cat $tempdir/orgs_filtred >> ${out} ; else
cat $tempdir/pwhois_org | grep -s -E -i -w "^Org-ID:|^Org-Name:|^Country:|^Geo-Country:|^NOC-0-Handle:" | sed '/Org-ID/{x;p;x;}' |
cut -d ' ' -f 2- | sed 's/^ *//' ; fi ; done | tee -a ${out}
for oid in $(cat $targets) ; do
f_netBLOCKS "${oid}" ; done | tee -a ${out} ; echo '' ; f_removeDir ; f_Menu
;;
4)
#************** pwhois.org BULK LOOKUPS *******************
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
echo '' ; sudo ${PATH_nmap} -sS -Pn -p ${ports} --script path-mtu $x | tee -a ${out} ; done
echo '' ; f_removeDir ; f_Menu
;;
t2)
#************** TRACEPATH *******************
f_makeNewDir ; f_Long
echo -e "\n${B}Options > TRACEPATH > ${G2} Mode\n"
echo -e "${B} [1]${D} IPv4"; echo -e "${B} [2]${D} IPv6" ; echo -e "${B} [3]${D} Auto (default)"
echo -e -n "\n${B}?${D} " ; read IPvChoice
echo -e -n "\n${B}Target  > [1]${D} Set target (hostname, IPv4 ${B}| [2]${D} Target list  ${B}?${D}  " ; read option_target
if [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target  > ${D}PATH TO FILE ${B}>>${D}  " ; read input
targets="$input" ; else
echo -e -n "\n${B}Set     >${G2} TARGET  ${B}>>${D}  " ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list" ; fi
echo -e -n "\n${B}Set     >${G2} HOPS ${B}>${D} Max. number of Hops (default:30) ${B}>>${D}  "; read hops
if [ $IPvChoice = "1" ] ; then
path_array+=(-4 -b)
elif [ $IPvChoice = "2" ]; then
path_array+=(-6 -b) ; else
path_array+=(-b) ; fi
for x in $(cat "$targets") ; do
out="${outdir}/ROUTES.${x}.txt" ; f_Long | tee -a ${out}; echo -e "TRACEPATH" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; echo -e "$x"
echo -e "$(date)\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' ; ${PATH_tracepath}  ${path_array[@]} -m ${hops} $x ; done | tee -a ${out}
echo '' ; f_removeDir ; f_Menu
;;
t3)
#************** MTR (local installation) *******************
f_makeNewDir; f_Long; domain_enum="false"; option_detail="1"; target_type="hop"; option_bl="n"
echo -e -n "\n${B}Target  > [1]${D} Set target (hostname, IPv4 or IPv6) ${B}| [2]${D} Target list  ${B}?${D}  " ; read option_target
if [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target  > ${G2}PATH TO FILE ${B}>>${D}  " ; read input
targets="$input" ; else
echo -e -n "\n${B}Target  > ${G2}IPv4/IPv6 ADDRESS / HOSTNAME  ${B}>>${D}  " ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list" ; fi
declare -a mtr_array=()
echo -e -n "\n${B}Option  > ${G2} Hop Details >${D} Look up Whois-, Geolocation- & RPKI- Info ${B} [y] | [n]  ?${D}  " ; read hop_details
echo -e -n "\n${B}Options > [1]${D} IPV4 MODE  ${B}| [2]${D}  IPV6 MODE ${B}| [3]${D}  AUTO (DEFAULT)  ${B}?${D}  " ; read IPvChoice
if  [ $IPvChoice = "1" ] ; then
mtr_array+=(-4 -b -z)
elif  [ $IPvChoice = "2" ] ; then
mtr_array+=(-6 -z -n) ; else
mtr_array+=(-z) ; fi
echo -e -n "\n${B}Option  > ${G2} Max. hops (default 30): ${B}max hops  >>${D}  " ; read hops
mtr_array+=(-m ${hops})
echo -e -n "\n${B}Option  > ${G2} No of pings (e.g. 5) ${B}>>${D}  " ; read pingcount
mtr_array+=(-c ${pingcount})
echo -e -n "\n${B}Options >${G2}  Protocols${B} > [1]${D}  TCP  ${B}| [2]${D}  UDP  ${B}| [3]${D}  ICMP  ${B}?${D}  " ; read protocol_input
if  [ $protocol_input = "1" ] ; then
echo -e -n "\n${B}Option  >${G2}  Target Port (e.g. 25)  ${B}>>${D}  " ; read tport
mtr_array+=(--tcp -P $tport) ; mtr_protocol="TCP"
elif [ $protocol_input = "2" ] ; then
mtr_array+=(--udp) ; mtr_protocol="UDP" ; else
mtr_protocol="ICMP" ; fi
for x in $(cat "$targets") ; do
out="${outdir}/ROUTES.${x}.txt" ; f_MTR "${x}"
if [ $hop_details = "y" ] ; then
type_hop="true" ; domain_enum="false" ; echo '' | tee -a ${out}
if  [ $IPvChoice = "1" ] ; then
hoplist=$(cat $tempdir/mtr.txt | grep -E "[0-9]." | awk -F' ' '{print $3 $4}' | egrep -s -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' |
sed '1,2d' | sed '/???/d'); else
hoplist=$(grep -E "[0-9]{1,2}\." $tempdir/mtr.txt | awk '{print $3}') ; fi
for i in $hoplist ; do
f_HOP "${i}" ; done | tee -a ${out} ; fi ; done
echo '' ; f_removeDir ; f_Menu
;;
t4)
#************** MTR (via hackertarget.com IP Tools API) *******************
f_makeNewDir ; f_Long; echo -e -n "\n${B}MTR (API) > Target >  ${G2}HOSTNAME, IPv4 ADDRESS ${B}>>${D}  " ; read target
out="${outdir}/ROUTES.${target}.txt"; echo ''; f_MTR_HT "${target}" | tee -a ${out}; echo ''; f_removeDir; f_Menu
;;
t5)
#************** NMAP (script traceroute-geolocation.nse) *******************
f_makeNewDir; f_Long; domain_enum="false"; option_detail="1"; target_type="hop"; option_bl="n"
echo -e "\n${B}NMAP NSE Geo Traceroute${D}"
echo -e -n "\n${B}Target > ${D}HOSTNAME(s)${B} | ${D}IP(s)${B}  >>${D}   " ; read target
out="${outdir}/ROUTES.${target}.txt"
echo '' ; f_Long | tee -a ${out} ; echo "[+] NMAP GEO TRACEROUTE | $target" | tee -a ${out} ; f_Long | tee -a ${out}; echo '' | tee -a ${out}
sudo ${PATH_nmap} -sn -Pn --traceroute --script traceroute-geolocation $target > $tempdir/geotrace
cat $tempdir/geotrace | sed '/^|/!d' | sed '1,1d' | sed '/HOP/{x;p;x;G}' | sed 's/|//' | tee -a ${out}; echo ''  | tee -a ${out}
hoplist=$(cat $tempdir/geotrace | sed '/^|/!d' | egrep -s -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sed '1,1d')
for i in $hoplist ; do
f_HOP "${i}" ; done | tee -a ${out} ; echo '' ; f_removeDir ; f_Menu
;;
t6)
#************** atk6-trace6  *******************
f_makeNewDir; f_Long; domain_enum="false"; option_detail="1"; target_type="hop"; option_bl="n"
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
sudo ${PATH_trace6} -t -d ${interface} ${x} > $tempdir/trace6
cat $tempdir/trace6 | sed '/Trace6 for/G' | tee -a ${out}
hops=$(awk -F' ' '{print $2}' $tempdir/trace6 | sed '1,1d' | sed '/!!!/d' | sed '/???/d' | sed 's/^ *//' | sed '/^$/d')
for i in $hops ; do
f_HOP "${i}" ; done | tee -a ${out} ; done  ; f_removeDir ; f_Menu
;;
t7)
#************** DUBLIN TRACEROUTE *******************
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
echo '' ; sudo ${PATH_dublin_t} -n 12 $x | sed '/Flow ID/{x;p;x;G;}' | tee -a ${out} ; done
f_removeDir ; f_Menu
;;
#************** NMAP - GENERAL PORT-/SERVICE-/VULNERABILITY SCAN OOPTIONS *******************
p1)
f_makeNewDir ; f_Long
if ! [ $option_connect = "0" ] ; then
declare -a nmap_array=()  ; declare -a port_array=()
echo -e "\n${B}Options > ${G2}Nmap Scan Types \n"
echo -e "${B} [1]${D} TCP Connect Scan (non-root)" ; echo -e "${B} [2]${D} Basic SYN Scan"
echo -e "${B} [3]${D} Service Version Scan (optional: vulners)" ; echo -e "${B} [4]${D} Service- & OS- Version Scan (optional: vulners)"
echo -e "${B} [5]${D} Service, OS & Vulnerability Scan (intrusive)"
echo -e -n "\n${B}  ?${D}  " ; read scan_type
echo -e -n "\n${G2}Mode   ${B}>  [1]${D}  IPv4   ${B}|  [2]${D}  IPv6  ${B}?${D}  " ; read option_ipv
echo -e -n "\n${G2}Target ${B}>  [1]${D} Set new target  ${B}| [2]${D} Read targets from list ${B}?${D}  " ; read option_target
if [ $option_target = "2" ] ; then
echo -e -n "\n${G2}Target ${B}>  ${D}PATH TO FILE ${B}>>${D}  " ; read input ; target="-iL ${input}"
if [ $report = "true" ] ; then
echo -e -n "\n${G2}Set   ${B}> ${D}OUTPUT - FILE NAME  ${B}>>${D}  " ; read filename ; else
filename="nmap_output"; fi; else
if [ $option_ipv = "2" ] ; then
nmap_array+=(-6); echo -e -n "\n${G2}Target ${B}>  ${D}Hostname(s)   ${B}|${D} IPv6 Address(es)  ${B}>>${D}  " ; read target ; else
echo -e -n "\n${G2}Target ${B}>  ${D}Hostname(s)   ${B}|${D} IPv4 Address(es)  ${B}|${D}  Network(s)  ${B}>>${D}  " ; read target ; fi
if [ $report = "true" ] ; then
if [[ $(echo "$target" | wc -w) -gt 1 ]]; then
echo -e -n "\n${G2}Set   ${B}> ${D}OUTPUT - FILE NAME  ${B}>>${D}  " ; read filename ; else
filename=$(echo $target | cut -d '/' -f 1); fi; else
filename="nmap_output"; fi; fi
echo -e "\n\n${B}Target Ports  >\n"; echo -e "${B} [1]${D} nmap Top 100 Ports"
echo -e "${B} [2]${D} nmap Top 1000 Ports" ; echo -e "${B} [3]${D} $ports_web2"
echo -e "${B} [4]${D} $ports_dns" ; echo -e "${B} [5]${D} All (TCP Ports)" ; echo -e "${B} [6]${D} Customize ports"
echo -e -n "\n${B}  ?${D}  " ; read portChoice
if   [ $portChoice = "1" ] ; then
if [ $scan_type = "1" ] ; then
port_array+=(--top-ports 100)
scripts="$nse_basic,$nse_ssh,$nse_web_safe,$nse_dns1"
elif [ $scan_type = "5" ] ; then
scripts="$nse_basic,$nse_ssh,$nse_web_safe,$nse_web1,$nse_dns2,$nse_dns3,unusual-port,smtp-strangeport,vulners"; else
scripts="$nse_basic,$nse_ssh,$nse_web_safe,$nse_dns2"; fi
elif [ $portChoice = "2" ] ; then
port_array+=(--top-ports 1000)
if [ $scan_type = "1" ] ; then
scripts="$nse_basic,$nse_ssh,$nse_web_safe,$nse_dns1"
elif [ $scan_type = "5" ] ; then
scripts="$nse_basic,$nse_web_safe,$nse_web1,$nse_dns1,$nse_dns2,$nse_dns3,unusual-port,smtp-strangeport,vulners"; else
scripts="$nse_basic,$nse_ssh,$nse_web_safe,$nse_dns1,$nse_dns2"; fi
elif [ $portChoice = "3" ] ; then
port_array+=(-p ${ports_web2})
if [ $scan_type = "1" ] ; then
scripts="$nse_basic,$nse_ssh,$nse_web_safe"
elif [ $scan_type = "5" ] ; then
scripts="$nse_basic,$nse_web_safe,$nse_web1" ; else
scripts="$nse_basic,$nse_ssh,$nse_dns2" ; fi
elif [ $portChoice = "4" ] ; then
port_array+=(-p ${ports_dns})
if [ $scan_type = "1" ] ; then
scripts="$nse_ssh,$nse_dns1"
elif [ $scan_type = "5" ] ; then
scripts="$nse_ssh,$nse_dns2,$nse_dns3"; else
scripts="$nse_ssh,$nse_dns2" ; fi
elif [ $portChoice = "5" ] ; then
port_array+=(-p-)
if [ $scan_type = "1" ] ; then
scripts="$nse_ssh,$nse_dns1"
elif [ $scan_type = "5" ] ; then
scripts="$nse_basic,$nse_web_safe,$nse_web1,$nse_dns2,$nse_dns3,smtp-strangeport,unusual-port,vulners"; else
scripts="$nse_ssh,$nse_dns2" ; fi ; else
echo -e -n "\n${B}Ports  > ${D} e.g. 636,989-995  ${B}>>${D}  " ; read ports
if [ $scan_type = "5" ] ; then
scripts="$nse_basic,$nse_web_safe,$nse_web1,$nse_dns2,$nse_dns3,smtp-strangeport,vulners"; else
scripts="$nse_basic,$nse_ssh,$nse_web_safe"; fi
port_array+=(-p ${ports}) ; fi
if   [ $scan_type = "1" ] ; then
nmap_array+=(-sT --open)
elif [ $scan_type = "2" ] ; then
if [ $portChoice = "4" ] || [ $portChoice = "5" ] ; then
nmap_array+=(-sS -sU --open); else
nmap_array+=(-sS --open); fi
elif [ $scan_type = "3" ] ; then
if [ $portChoice = "4" ] || [ $portChoice = "5" ] ; then
nmap_array+=(-sV -sUV --open) ; else
nmap_array+=(-sV --open); fi
elif [ $scan_type = "4" ] ; then
if [ $portChoice = "4" ] || [ $portChoice = "5" ] ; then
nmap_array+=(-sV -sUV -O --open) ; else
nmap_array+=(-sV -O --open); fi ; fi
if ! [ $scan_type = "5" ] ; then
echo -e "\n${B}Options > ${G2}NSE Scripts\n"
echo -e "${B} [1]${D} Run NSE Scripts (category: 'safe')" ; echo -e "${B} [2]${D} Don't use any additional scripts"
if [ $scan_type = "3" ] || [ $scan_type = "4" ] ; then
echo -e "${B} [3]${D} Run NSE Scripts, incl. CVE vulners (all in category 'safe')" ; fi
echo -e -n "\n${B}  ?${D}  " ; read option_nse ; fi
out="${outdir}/$filename"
if [ $scan_type = "5" ] ; then
sudo ${PATH_nmap} ${nmap_array[@]} ${port_array[@]} ${target} -oA ${out} --script ${scripts} > $tempdir/nmap.txt ; else
if [ $option_nse = "2" ] ; then
if [ $scan_type = "1" ] ; then
${PATH_nmap} ${nmap_array[@]} -oA ${out} ${port_array[@]} ${target} > $tempdir/nmap.txt; else
sudo ${PATH_nmap} ${nmap_array[@]} -oA ${out} ${port_array[@]} ${target} > $tempdir/nmap.txt; fi ; else
if [ $scan_type = "1" ] ; then
${PATH_nmap} ${nmap_array[@]} -oA ${out} ${port_array[@]} ${target} --script ${scripts} > $tempdir/nmap.txt; else
if [ $option_nse = "1" ] ; then
sudo ${PATH_nmap} ${nmap_array[@]} ${port_array[@]} ${target} -oA ${out} --script ${scripts} > $tempdir/nmap.txt
elif [ $option_nse = "3" ] ; then
sudo ${PATH_nmap} ${nmap_array[@]} ${port_array[@]} ${target} -oA ${out} --script ${scripts},${scripts2},vulners > $tempdir/nmap.txt; fi; fi ; fi ; fi
echo -e "\n" | tee -a ${out}.txt; f_Long | tee -a ${out}.txt; echo -e "[+] $x | NMAP SCAN | $(date)" | tee -a ${out}.txt
f_NMAP_OUT | tee -a ${out}.txt; echo '' | tee -a ${out}.txt ; else
f_WARNING ; fi ; f_removeDir ; f_Menu
;;
p2)
#************** NMAP PORT SCAN (via hackertarget.com IP Tools API) *******************
f_makeNewDir ; f_Long ; echo -e -n "\n${B}Nmap > Target >${D} IPv4 ADDRESS  >>${D}  " ; read target
out="${outdir}/PORTSCAN.${target}.txt"; f_NMAP_HT "${target}" | tee -a ${out}; f_removeDir ; f_Menu
;;
p3)
#*************** NMAP - FIREWALK / TCP FLAGS, FRAGMENTATION, SOURCE PORT SPOOFING *******************
f_makeNewDir ; f_Long ; scripts=''
echo -e "\n${B}NMAP > ${G2} Firewalk, TCP Flags\n${D}"
if ! [ $option_connect = "0" ] ; then
declare -a nmap_array=() ; nmap_array+=(--reason) ; declare -a port_array=()
echo -e "\n${B}Options >\n"
echo -e "${B} [1]${D} TCP Flag Scan (ACK,FIN etc.)" ; echo -e "${B} [2]${D} Firewalk"
echo -e "${B} [3]${D} BOTH" ; echo -e -n "\n${B}  ?${D}  " ; read scan_type
echo -e -n "\n${B}Mode    >  [1]${D}  IPv4   ${B}|  [2]${D}  IPv6  ${B}?${D}  " ; read option_ipv
echo -e -n "\n${G2}Target ${B}>  [1]${D} Set new target  ${B}| [2]${D} Read targets from list ${B}?${D}  " ; read option_target
if [ $option_target = "2" ] ; then
echo -e -n "\n${G2}Target ${B}>  ${D}PATH TO FILE ${B}>>${D}  " ; read input ; target="-iL ${input}"
if [ $report = "true" ] ; then
echo -e -n "\n${G2}Set   ${B}> ${D}OUTPUT - FILE NAME  ${B}>>${D}  " ; read filename ; else
filename="nmap_output"; fi; else
if [ $option_ipv = "2" ] ; then
nmap_array+=(-6); echo -e -n "\n${G2}Target ${B}>  ${D}Hostname(s)   ${B}|${D} IPv6 Address(es)  ${B}>>${D}  " ; read target ; else
echo -e -n "\n${G2}Target ${B}>  ${D}Hostname(s)   ${B}|${D} IPv4 Address(es)  ${B}|${D}  Network(s)  ${B}>>${D}  " ; read target ; fi
if [ $report = "true" ] ; then
if [[ $(echo "$target" | wc -w) -gt 1 ]]; then
echo -e -n "\n${G2}Set   ${B}> ${D}OUTPUT - FILE NAME  ${B}>>${D}  " ; read filename ; else
filename=$(echo $target | cut -d '/' -f 1); fi; else
filename="nmap_output"; fi; fi
echo -e "\n\n${B}Target Ports  >\n"
echo -e "${B} [1]${D} nmap Top 20 Ports" ; echo -e "${B} [2]${D} nmap Top 100 Ports"
echo -e "${B} [3]${D} Custom Port List"
echo -e -n "\n${B}  ?${D}  " ; read portChoice
if   [ $portChoice = "1" ] ; then
port_array+=(--top-ports 20)
elif [ $portChoice = "2" ] ; then
port_array+=(--top-ports 100) ; else
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
out="${outdir}/$filename"
sudo ${PATH_nmap} ${nmap_array[@]} ${port_array[@]} ${target} -oA ${out} --script ${scripts} > $tempdir/nmap.txt
if [ $scan_type = "1" ] || [ $scan_type = "3" ] ; then
if [ $scan_flag = "3" ] ; then
sudo ${PATH_nmap} ${nmap2_array[@]} ${port_array[@]} ${target} -oA 2.${out} > $tempdir/nmap.txt; fi; fi
echo -e "\n" | tee -a ${out}.txt
if [ $scan_type = "2" ] ; then
f_Long | tee -a ${out}.txt; echo "NMAP | $target | $(date)" | tee -a ${out}.txt; f_Long | tee -a ${out}.txt ; else
f_Long | tee -a ${out}.txt; echo "NMAP | $target | $flag | $(date)" | tee -a ${out}.txt; f_Long | tee -a ${out}.txt ; fi
cat $tempdir/nmap.txt | sed '/PORT/{x;p;x;G}' | sed '/Starting Nmap/d' | sed '/Read data files/d' | sed '/NSE/d' | sed '/Initiating/d' |
sed '/Completed/d' | sed '/Service detection/d' | sed '/\/tcp /G' | sed 's/Nmap scan report for/*/' | sed '/Host is/{x;p;x;}' | fmt -s -w 120 | tee -a ${out}.txt
if [ -f $tempdir/nmap2.txt ] ; then
echo -e "\n" | tee -a ${out}.txt
f_Long | tee -a ${out}.txt; echo "NMAP | $target | ACK SCAN | $(date)" | tee -a ${out}.txt; f_Long | tee -a ${out}.txt
cat $tempdir/nmap2.txt | sed '/PORT/{x;p;x;G}' | sed '/Starting Nmap/d' | sed '/Read data files/d' | sed '/NSE/d' | sed '/Initiating/d' |
sed '/Completed/d' | sed '/Service detection/d' | sed '/\/tcp /G' | sed 's/Nmap scan report for/*/' |
sed '/Host is/{x;p;x;}' | fmt -s -w 120 | tee -a ${out}.txt; fi ; else
f_WARNING ; fi ; f_removeDir ; f_Menu
;;
q)
echo -e "\n${B}----------------------------------- Done -------------------------------------\n"
echo -e "                       ${BDim}Author - Thomas Wy, Dec 2021${D}\n\n" ; f_removeDir
break
;;
esac
done
#!/bin/bash
#---------------------------------------- CONFIG - API KEYS -------------------------------------------------------
#* Set your API Keys
#-------------------
#hackertarget.com  -  expected input:  api_key_ht='&apikey=YOUR API KEY'
api_key_ht=''
# project honeypot
honeykey=''
#---------------------------------------- CONFIG - CUSTOMIZE PATHS TO EXECUTABLES  --------------------------------
PATH_dublin_t=$(command -v dublin-traceroute)
#PATH_dublin_t=""
PATH_dump_dhcp6=$(command -v atk6-dump_dhcp6)
#PATH_dump_dhcp6=""
PATH_dump_router6=$(command -v atk6-dump_router6)
#PATH_dump_router6=""
PATH_rdns6=$(command -v atk6-dnsrevenum6)
#PATH_rdns6=""
PATH_thcping6=$(command -v atk6-thcping6)
#PATH_thcping6=""
PATH_trace6=$(command -v atk6-trace6)
#PATH_trace6=""
PATH_httping=$(command -v httping)
#PATH_httping=""
PATH_ipcalc=$(command -v ipcalc)
#PATH_ipcalc=""
PATH_lbd=$(which lbd)
#PATH_lbd=""
PATH_lynx=$(command -v lynx)
#PATH_lynx=""
PATH_mtr=$(command -v mtr)
#PATH_mtr=""
PATH_nmap=$(command -v nmap)
#PATH_nmap=""
PATH_nping=$(command -v nping)
#PATH_nping=""
PATH_sipcalc=$(command -v sipcalc)
#PATH_sipcalc=""
PATH_sslscan=$(command -v sslscan)
#PATH_sslscan=""
PATH_testssl=$(command -v  testssl)
#PATH_testssl=""
PATH_tracepath=$(command -v tracepath)
#PATH_tracepath=""
PATH_wfuzz=$(command -v wfuzz)
#PATH_wfuzz""
PATH_whatweb=$(command -v whatweb)
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
ports_common="T:21,T:22,T:23,T:25,T:53,U:53,T:80,T88,T:110,U:123,T:135,T:139,T:143,T:443,T:445,T:465,T:514,T:587,T:993,T:995,T:1025,T:1434,T:3306,T:3389,U:5060,T:5222,T:8080,T:8333,T:8443"
ports_common_nonroot="21,22,23,25,53,80,88,110,135,443,465,514,587,993,995,1025,1434,3306,8080,8443"
ports_dns="U:53,T:22,T:23,T:25,T:53,T:80,T:110,T:143,T:443,T:465,T:587,T:993,T:995,T:5222"
ports_net="T:21,T:22,T:23,T:25,T:53,U:53,T:80,T:88,T:110,T:111,U:123,T:135,T:139,T:143,T:443,T:445,T:514,T:993,T:995,T:1025,T:1434,T:1723,T:3306,T:3389,T:5004,T:5005,U:5060,T:5222,T:5900,T:8080,T:8333,T:8443"
ports_lan="U:53,U:123,T:21,T:22,T:23,T:25,T:53,T:79,T:80,T:102,T:110,T:135,U:137,T:139,U:161,T:443,T:631,T:1025,T:1434,T:3306,T:3389,T:5004,T:5005,U:5060,T:5900,T:8080,U:3671,U:47808,T:102,T:502"
ports_web1="T:80,T:443,T:3306"
ports_web2="T:21,T:22,T:23,T:80,T:443,T:3306"
ports_web3="T:21,T:22,T:23,T:80,T:443,T:1434,T:3306,T:3389,T:8080,T:8443,T:10000"
ports_web4="T:21,T:22,T:23,T:25,T:53,T:80,T:443,T:1099,T:1434,T:3306,T:3389,T:8009,T:8080,T:8443,T:9800,T:10000,T:50070,T:50075"
nse_basic_nonroot="banner,https-redirect,http-server-header,ip-geolocation-geoplugin"
nse_basic_nonroot6="address-info,banner,https-redirect,http-server-header,ip-geolocation-geoplugin"
nse_01_nonroot="ssh-auth-methods,ssh2-enum-algos,ssl-cert,smtp-commands,smtp-ntlm-info,imap-capabilities,imap-ntlm-info,pop3-capabilities,mysql-info"
nse_basic="banner,http-server-header,https-redirect,ip-geolocation-geoplugin,unusual-port"
nse_basic6="address-info,banner,https-redirect,http-server-header,ip-geolocation-geoplugin,unusual-port"
nse_01="ssh-auth-methods,ssh2-enum-algos,ssl-cert,smtp-commands,smtp-ntlm-info,imap-capabilities,imap-ntlm-info,pop3-capabilities,sip-methods,mysql-info"
nse_02="hadoop-namenode-info,hadoop-datanode-info,hadoop-jobtracker-info,rpcinfo,vmware-version"
nse_vulners_01="http-malware-host,smtp-strangeport,mysql-empty-password,ms-sql-empty-password,ftp-anon,dns-recursion,vulners"
nse_vulners_02="http-methods,http-csrf,http-dombased-xss,http-referer-checker,http-stored-xss,http-unsafe-output-escaping,http-open-proxy,smtp-enum-users,smtp-open-relay,http-slowloris-check,smb-double-pulsar-backdoor,vulners"
nse_dns_01="smtp-commands,smtp-ntlm-info,imap-capabilities,imap-ntlm-info,pop3-capabilities,dns-recursion,http-server-header,ssl-cert,vulners"
nse_dns_02="smtp-open-relay,smtp-enum-users"
nse_dns_03="ssh2-enum-algos,ssh-auth-methods,,http-malware-host,http-methods,http-dombased-xss,http-stored-xss,http-open-proxy"
nse_net="banner,bitcoin-info,cups-info,hadoop-namenode-info,http-server-header,ssl-cert,smb-enum-shares,nfs-showmount,ntp-info,unusual-port"
nse_lan="bacnet-info,banner,bitcoin-info,cups-info,finger,http-server-header,knx-gateway-discover,modbus-discover,mysql-info,s7-info,smb-enum-shares,nfs-showmount,ntp-info,ssl-cert,smb-os-discovery,snmp-netstat,rpcinfo"
nse_lan_vulners_safe="ssh-auth-methods,ssh2-enum-algos,http-malware-host,dns-recursion,vulners"
nse_lan_vulners_intrusive="smb-double-pulsar-backdoor,mysql-empty-password,ms-sql-empty-password,ftp-anon,http-methods,smtp-open-relay"
nse_lan_vulners_intrusive="smb-double-pulsar-backdoor,mysql-empty-password,ms-sql-empty-password,ftp-anon,http-methods,smtp-open-relay"
nse_iot="bacnet-info,knx-gateway-discover,modbus-discover,s7-info"
nse_web_safe="http-apache-server-status,http-generator,http-php-version,http-mobileversion-checker,http-affiliate-id,http-referer-checker,mysql-info"
nse_web_safe_root="http-apache-server-status,http-generator,http-php-version,http-mobileversion-checker,http-affiliate-id,http-referer-checker,mysql-info,vulners"
nse_web1="ftp-anon,http-auth,http-auth-finder,http-csrf,http-dombased-xss,http-enum,http-generator,http-malware-host,http-mobileversion-checker,http-methods,http-php-version,https-redirect,http-referer-checker,http-stored-xss,http-unsafe-output-escaping,mysql-empty-password,xmlrpc-methods,ssh-auth-methods,ssh2-enum-algos,http-wordpress-enum"
nse_web1_root="ftp-anon,http-auth,http-auth-finder,http-csrf,http-dombased-xss,http-enum,http-generator,http-malware-host,http-mobileversion-checker,http-methods,http-php-version,https-redirect,http-referer-checker,http-stored-xss,http-unsafe-output-escaping,mysql-empty-password,xmlrpc-methods,ssh-auth-methods,ssh2-enum-algos,http-wordpress-enum,vulners"
nse_web2="http-drupal-enum,http-jsonp-detection,http-open-proxy,http-backup-finder,smtp-strangeport,http-slowloris-check,hadoop-namenode-info,hadoop-datanode-info,hadoop-jobtracker-info,rpcinfo,vmware-version"

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
dnsbl-1.uceprotect.net
dnsbl-2.uceprotect.net
dnsbl-3.uceprotect.net
dnsbl.dronebl.org
dnsbl.tornevall.org
ips.backscatterer.org
ix.dnsbl.manitu.net
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
ips.backscatterer.org
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
ix.dnsbl.manitu.net
phishing.rbl.msrbl.net
recent.spam.dnsbl.sorbs.net
smtp.dnsbl.sorbs.net
talosintelligence.com
tor.dan.me.uk
"
blocklists_hop="
all.s5h.net
b.barracudacentral.org
bl.spamcop.net
dnsbl-1.uceprotect.net
dnsbl-2.uceprotect.net
dnsbl-3.uceprotect.net
ix.dnsbl.manitu.net
talosintelligence.com
"
#********************** MAIN MENU (GLOBAL OPTIONS) & BANNER ***********************
f_Menu(){
out="$tempdir/out"; file_date=$(date +"%b.%d.%Y")
echo -e "\n  ${B}Directory      >${D}  $folder"
echo -e "\n  ${B}TargetConnect  >  $conn\n\n"
echo -e "${B}    a)   ${D}Abuse Contact Finder"
echo -e "${B}   as)   ${D}ASNs, BGP, IX"
echo -e "${B}   bl)   ${D}Blocklists"
echo -e "${B}    d)   ${D}Domain Recon"
echo -e "${B}  dns)   ${D}DNS, MX, NS"
echo -e "${B}    g)   ${D}Rev. Google Analytics Search"
echo -e "${B}    i)   ${D}Netw.Interfaces, Public IP"
echo -e "${B}   ip)   ${D}IP Addresses / Hostnames"
echo -e "${B}    l)   ${D}LAN"
echo -e "${B}    m)   ${D}MTU"
echo -e "${B}    n)   ${D}Networks & Prefixes"
echo -e "${B}    p)   ${D}Ping Probes, Port Scans, Firewalk"
echo -e "${B}    t)   ${D}Traceroute Options"
echo -e "${B}    w)   ${D}Whois (Advanced & Bulk Lookup Options)"
echo -e "${B}  www)   ${D}Web Servers"
echo -e "\n${B}    c)   TOGGLE TARGET - CONNECT / NON-CONNECT MODE"
echo -e "   cc)   CLEAR THE SCREEN"
echo -e "    h)   HELP"
echo -e "    s)   SAVE RESULTS"
echo -e "    q)   QUIT${D}"
}

echo -e " ${B}
  ____                _           
 |  _ \ _ ____      _| |__   ___  
 | | | | '__\ \ /\ / / '_ \ / _ \ 
 | |_| | |   \ V  V /| | | | (_) |
 |____/|_|    \_/\_/ |_| |_|\___/ 
 ${D}"
echo -e "\033[3;39m  \"whois the Doctor? Who? Dr Who?\" ${D}"
echo ''; f_Menu

#********************** MANAGE TARGET INTERACTION ***********************
f_targetCONNECT() {
echo -e "\n${B}Option >${G2} Target Interaction ${B}>${D} Send packets from your IP to target systems?"
echo -e "\n${G2}[1] YES${D}\n"
echo "(Recommended for domain recon, required for web server- & most traceroute-, ping- & port scan options)"
echo -e "\n${R}[0] NO ${D}\n"
echo "(Interaction with target systems via 3rd party sources only; default for option ip) IP Addresses / Hostnames)"
echo -e -n "\n\n${B}  ?${D}  " ; read option_connect
if ! [ $option_connect = "0" ] ; then
conn="${GREEN}true${D}" ; else
conn="${R}false${D}" ; fi
export option_connect ; export conn; f_Long
}
f_WARNING(){
echo -e "\n${R}  Warning >${D} This option requires sending packets to target systems!"
echo -e "\n  Please deactivate safe mode via option c)" ; echo -e "\n  ${R}${IT}Aborting...${D}"
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
local s="$*"; rir=$(curl -s -m 7 --location --request GET "https://stat.ripe.net/data/rir/data.json?resource=${s}" | jq -r '.data.rirs[0].rir' |
cut -d ' ' -f 1 | tr -d ' ' | tr [:upper:] [:lower:]); export rir
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
f_Long; echo -e "INTERFACES\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
if [[ $(uname -o) =~ "Android" ]] ; then
echo -e "ETHERNET"
ip addr show | grep -B 1 -w 'link/ether' | grep -A 1 -w 'state UP' | cut -d ' ' -f 2- | sed 's/^ *//' | sed 's/link\/ether/ link\/ether/g' |
sed '/state UP/{x;p;x;G}' | sed 's/: </: \n\n </g' ; echo -e "\n\nIPV4"
ip -4 addr show | grep -A 2 'state UP' | cut -d ' ' -f 2- | sed 's/^ *//' | sed 's/inet/ inet/g' | sed 's/valid_lft/ valid_lft/g' |
sed '/state UP/{x;p;x;G}' | sed '/valid_lft/{x;p;x;G}' | sed 's/: </: \n\n </g'; echo -e "\n\nIPV6"
ip -6 addr show | grep -A 2 'state UP' | cut -d ' ' -f 2- | sed 's/^ *//' | sed 's/inet/ inet/g' | sed 's/valid_lft/ valid_lft/g' |
sed '/state UP/{x;p;x;G}' | sed '/valid_lft/{x;p;x;G}' | sed 's/: </: \n\n </g'
f_Long; echo -e "ROUTES\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' ; ip route; else
nmap --iflist > $tempdir/iflist; sed -n '/INTERFACES/,/ROUTES/p' $tempdir/iflist | grep -E -v "INTERFACES|ROUTES" | sed '/MTU/{x;p;x;G;}'
f_Long; echo -e "ROUTES\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; sed -n '/ROUTES/,$p' $tempdir/iflist | grep -E -v "ROUTES" |
sed '/METRIC/{x;p;x;G}'; fi; echo ''
}
#********************** TEXT OUTPUT / NMAP / BANNER GRAB ***********************
f_textfileBanner(){
local s="$*";echo -e "\n ---------------" ; echo -e "  drwho.sh" ; echo -e " ---------------\n"
echo -e "https://github.com/ThomasPWy/drwho.sh,  Author: Thomas Wy,  Version: 2.2 (Feb 2022)"; f_Long
echo -e "\nDate:    $(date)"; echo -e "\nTarget:  $s\n"
}
f_whoisFORMAT(){
cat $tempdir/whois_temp | sed 's/% Information related to /Information related to /' | sed '/Source:/d' | sed '/fax:/d' | sed '/remarks:/d' |
sed 's/% Abuse contact/Abuse contact/' | sed '/^#/d' | sed '/%/d' | sed '/^$/d' | sed '/Abuse contact/{x;p;x;G;}' |
sed 's/Abuse contact for .*. is/\[@\] /' | sed '/Information related/i \_______________________________________________________________________________\n' |
sed '/Information related/G' | sed 's/Information related to/* /'
}
f_NMAP_OUT2(){
local s="$*"
grep -E "Nmap scan report|rDNS|PORT|[0-9]{1,5}/tcp|[0-9]{1,5}/udp|\||\|_|CVE.*|MAC|OS|Device type:|Running:|Distance:|Info:|results:|Nmap done"  $s |
sed 's/PORT/\n\nPORT/g' | sed '/\/tcp /G'| sed '/\/udp /G' | sed '/Nmap scan report for/G' | sed 's/OS guesses:/OS guesses:\n/g' |
sed '/Nmap scan report/i \\n_______________________________________________________________________________\n' | sed '/Nmap done/{x;p;x;G}' |
sed 's/Nmap scan report for/\n*/g' |  sed 's/Device type:/Device type:       /g' | sed 's/^|_//g' | sed 's/^|//g' |
sed '/\/tcp/i \\n-------------------------------------------------------------------------------\n' | sed '/CVE/G' | sed '/cpe:/G' |
sed '/\/udp/i \\n-------------------------------------------------------------------------------\n' | sed 's/^[ \t]*//;s/[ \t]*$//' |
sed '/Network Distance:/i \\n-------------------------------------------------------------------------------\n' | sed 's/banner:/\nbanner:\n/g' |
sed '/OS guesses:/i \\n-------------------------------------------------------------------------------\n' | sed 's/Running:/\nRunning:    /g' |
sed '/Device type:/i \\n-------------------------------------------------------------------------------\n' |
sed 's/OS details:/\nOS details:        /' | sed '/OS and Service detection performed/d' | sed 's/No exact OS matches/\n No exact OS matches/g' |
sed '/No mobile version detected./d' | sed 's/address-info:/\naddress-info:\n/g' | sed 's/bacnet-discover:/\nbacnet-discover:\n/g' |
sed 's/cups-info:/\ncups-info:\n/g' | sed 's/dns-nsid:/\ndns-nsid:\n/g' |
sed 's/dns-recursion:/\ndns-recursion:\n/g' | sed 's/finger:/\nfinger:\n/g' | sed 's/Host script results:/\nHost script results:\n/g' |
sed 's/http-affiliate-id:/\nhttp-affiliate-id:\n/g' | sed 's/http-auth:/\nhttp-auth:\n/g' | sed 's/http-auth-finder:/\nhttp-auth-finder:\n/g' |
sed 's/http-csrf:/\nhttp-csrf:\n/g' | sed 's/http-cross-domain-policy:/\nhttp-cross-domain-policy:\n/g' | sed 's/http-enum:/\nhttp-enum:\n/g' |
sed 's/http-dombased-xss:/\nhttp-dombased-xss:\n/g' | sed 's/http-generator:/\nhttp-generator:\n/g' | sed 's/http-malware-host:/\nhttp-malware-host:\n/g' |
sed 's/http-methods:/\nhttp-methods:/g' | sed 's/http-mobileversion-checker:/\nhttp-mobileversion-checker:\n/g' |
sed 's/http-open-redirect:/\nhttp-open-redirect:\n/g' | sed 's/http-php-version:/\nhttp-php-version:\n/g' |
sed 's/http-unsafe-output-escaping:/\nhttp-unsafe-output-escaping:\n/g' | sed 's/http-referer-checker:/\nhttp-referer-checker\n/g' |
sed 's/http-stored-xss:/\nhttp-stored-xss:\n/g' | sed 's/Methods:/Methods: /g' | sed 's/Potentially risky methods:/Potentially Risky: /g' |
sed 's/http-jsonp-detection:/\nhttp-jsonp-detection:\n/g' | sed 's/proxy-open-http:/\nproxy-open-http:\n/g' |
sed 's/http-slowloris-check:/\nhttp-slowloris-check:\n/g' | sed 's/http-wordpress-enum:/\nhttp-wordpress-enum:\n/g' |
sed 's/http-phpmyadmin-dir-traversal:/\nhttp-phpmyadmin-dir-traversal:\n/g' | sed 's/http-drupal-enum:/\nhttp-drupal-enum:\n/g' |
sed 's/http-webdav-scan:/\nhttp-webdav-scan:\n/g' | sed 's/http-backup-finder:/\nhttp-backup-finder:\n/g' |
sed 's/smtp-strangeport:/\nsmtp-strangeport:\n/g' | sed 's/hadoop-datanode-info:/\nhadoop-datanode-info:\n/g' |
sed 's/hadoop-namenode-info:/\nhadoop-namenode-info:\n/g' | sed 's/hadoop-jobtracker-info:/\nhadoop-jobtracker-info:\n/g' |
sed 's/imap-capabilities:/\nimap-capabilities:\n/g' | sed 's/imap-ntlm-info:/\nimap-ntlm-info:\n/g' | sed 's/knx-gateway-info:/\nknx-gateway-info:\n/g' |
sed 's/modbus-discover:/\nmodbus-discover:\n/g' | sed 's/ms-sql-info:/\nms-sql-info:\n/g' | sed 's/ms-sql-empty-password:/\nms-sql-empty-password:\n/g' |
sed 's/mysql-info:/\nmysql-info:\n/g' | sed 's/mysql-empty-password:/\nmysql-empty-password:\n/g' | sed 's/nat-pmp-info:/\nnat-pmp-info:\n/g' |
sed 's/nfs-showmount:/\nnfs-showmount:\n/g' | sed 's/ntp-info:/\nntp-info:\n/g' | sed 's/pop3-capabilities:/\npop3-capabilities:\n/g' |
sed 's/pop3-ntlm-info:/\npop3-ntlm-info:\n/g' | sed 's/rpcinfo:/\nrpcinfo:\n/g' | sed 's/smtp-commands:/\n\nsmtp-commands:\n/g' |
sed 's/This server supports the following commands:/\nThis server supports the following commands:\n/g' |
sed 's/smb-double-pulsar-backdoor:/\nsmb-double-pulsar-backdoor:\n/g' | sed 's/smb-enum-shares:/\nsmb-enum-shares:\n/g' |
sed 's/smtp-enum-users:/\nsmtp-enum-users:\n/g' | sed 's/smtp-open-relay:/\nsmtp-open-relay:\n/g' | sed 's/smtp-strangeport:/\nsmtp-strangeport:\n/g' |
sed 's/ssl-cert:/\nssl-cert:\n/g' | sed 's/ssh2-enum-algos:/\nssh2-enum-algos:\n/g' | sed 's/ssh-auth-methods:/\nssh-auth-methods:\n/g' |
sed 's/sip-methods:/\nsip-methods:\n/g' | sed 's/sip-enum-users:/\nsip-enum-users:\n/g' | sed 's/unusual-port:/\nunusual-port:\n/g' |
sed 's/vmware-version:/\nvmware-version:\n/g' | sed 's/vulners:/\n\nvulners:\n/g' | sed 's/xmlrpc-methods:/\nxmlrpc-methods:\n/g' |
sed 's/xmpp-info:/\nxmpp-info:\n/g' | sed '/Nmap done/d' | sed 's/^[ \t]*//;s/[ \t]*$//' | fmt -s -w 120 | tee $tempdir/nmap_output; echo ''
}
f_NMAP_OUT1(){
local s="$*"; cat $s | sed '/Nmap scan report/i \_______________________________________________________________________________\n' |
sed 's/Host is up/\nHost is up/g' | sed '/Nmap scan report/G' | sed 's/Nmap scan report for/\n*/g' | sed 's/Host is/  Host is/g' |
sed 's/Not shown:/  Not shown:/g' | sed 's/Some closed ports/  Some closed ports/g' | sed '/PORT/G' | sed 's/PORT/\n\nPORT/g' |
sed '/\/tcp/i \-------------------------------' | sed '/\/udp  open|filtered/i \-------------------------------------' |
sed '/MAC Address:/i \-------------------------------------\n' | sed '/\/tcp /{x;p;x;G}'| sed '/\/udp /{x;p;x;G}' |
sed '/Service Info:/{x;p;x;}' | grep -E -v "\| Public Key|\| MD5:|\| Signature Algorithm:" | sed 's/vulners:/vulners:\n/' |
sed '/Aggressive OS guesses:/G' | sed 's/Host is/  Host is/g' | sed 's/Running:/Running:           /g' |
sed 's/No exact OS matches/\n No exact OS matches/g' | sed 's/OS details:/\nOS details:        /' | sed '/OS and Service detection/d'
}
f_RUN_NMAP(){
local s="$*"; scan_target=$(echo $s | sed 's/http[s]:\/\///' | tr -d ' ')
scan_target_stripped=$(echo $s | sed 's/http[s]:\/\///' | cut -s -d '/' -f 1 | tr -d ' ')
scan_target_trimmed=$(echo $s | sed 's/http[s]:\/\///' | cut -d '/' -f 1 | tr -d ' ')
if [[ ${scan_target_trimmed} =~ $REGEX_IP4 ]] ; then
option_ipv="1"
if [ -n "$scan_target_stripped" ]; then
type_net="true"; else
type_net="false"; fi; else
if [[ $(host $scan_target_trimmed | grep -o -c 'ip6.arpa') -gt 0 ]]; then
option_ipv="2"
if [ -n "$scan_target_stripped" ]; then
type_net="true"; else
type_net="false"; fi; else
type_net="false"; fi; fi
if [ $option_ipv = "1" ]; then
if [ $option_root = "y" ] ; then
sudo ${PATH_nmap} ${nmap_array[@]} -p ${ports} ${scan_target} ${scripts} ${script_args} 2>/dev/null > $tempdir/nmap.t4.txt; else
${PATH_nmap} ${nmap_array[@]} -p ${ports} ${scan_target} ${scripts} ${script_args} 2>/dev/null > $tempdir/nmap.t4.txt; fi
if [ $type_net = "true" ]; then
f_NMAP_OUT1 "$tempdir/nmap.t4.txt"; else
f_NMAP_OUT2 "$tempdir/nmap.t4.txt"; fi; fi
if [ $option_ipv = "2" ]; then
if [ $option_root = "y" ] ; then
sudo ${PATH_nmap} -6 ${nmap_array[@]} -p ${ports} ${scan_target} ${scripts} ${script_args} 2>/dev/null > $tempdir/nmap.t6.txt; else
${PATH_nmap} -6 ${nmap_array[@]} -p ${ports} ${scan_target} ${scripts} ${script_args} 2>/dev/null > $tempdir/nmap.t6.txt; fi
if [ $type_net = "true" ]; then
f_NMAP_OUT1 "$tempdir/nmap.t6.txt"; else
f_NMAP_OUT2 "$tempdir/nmap.t6.txt"; fi; fi
}
f_NMAP_HT(){
local s="$*" ; echo '' ; f_Long; echo -e "NMAP\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
curl -s https://api.hackertarget.com/nmap/?q=${s}${api_key_ht} | sed '/PORT/{x;p;x;G}'
echo -e "\nSource: hackertarget.com IP API\n"
}
f_BANNERS(){
local s="$*" ; curl -s https://api.hackertarget.com/bannerlookup/?q=${s}${api_key_ht} > $tempdir/banners.json
jq -r '{IP: .ip, SSH: .ssh, FTP: .ftp, Telnet: .telnet, http80_Server: .http80.server, http80_Title: .http80.title, RDP: .rdp, https443_Server: .https443.server, https443_Title: .https443.title, https443_CN: .https443.cn, https443_Org: .https443.o, http8080_Server: .http8080.server, http8080_Title: .http8080.title, https8443_Server: .https8443.server, https8443_Title: .https8443.title, https8443_CN: .https8443.cn}' $tempdir/banners.json | tr -d '{,"}' |
sed 's/^ *//' | sed '/^$/d' | sed 's/Server: null/Server: unknown/g' | sed '/null/d' | sed '/^$/d' | sed 's/http8080_Server:/http9090_Server:/g' |
sed 's/https8443_Server:/https9553_Server:/g' | sed 's/http80_Title:/| Title:/g' | sed 's/https443_Title:/| Title:/g' | sed 's/https443_CN:/| CN:/g' |
sed 's/https443_Org:/| Org:/g' | sed 's/http8080_Title:/| Title:/g' | sed 's/https8443_Title:/| Title:/g' |
sed 's/https8443_CN:/| CN:/g' | tr '[:space:]' ' ' | sed 's/RDP:/\nRDP:/g' | sed 's/Telnet:/\nTelnet:/g' | sed 's/https443/\nhttps443/g' |
sed 's/http80/\nhttp80/g' | sed 's/http9090/\nhttp9090/g' | sed 's/https9553/\nhttps9553/g' | sed 's/IP:/\nIP:/g' | sed 's/FTP:/\nFTP:/g' |
sed 's/SSH:/\nSSH:/g' | sed 's/RDP:/\nRDP\n/g' | sed 's/Telnet:/\nTelnet\n/g' | sed 's/unknown |/un|/g' | sed '/unknown/d' |
sed 's/_Server:/ Server:/g' | sed 's/http80/\nhttp80/g' | sed 's/https443/\nhttps443/g' | sed 's/FTP:/\nFTP\n/g' | sed 's/SSH:/\nSSH\n/g' |
sed 's/IP:/\n\nIP:/g' | sed 's/server: //g' | sed 's/Server: un| //g' | sed 's/server://g' | sed 's/http80/80\/HTTP\n/g' |
sed 's/https443/443\/HTTPS\n/g' | sed 's/http9090/\n8080\/HTTP\n/g' | sed 's/https9553/\n8443\/HTTPS\n/g' | sed 's/^ *//' | sed 's/^/  /g' |
sed 's/  IP:/*/g'  > $tempdir/banners.txt; echo '' >> $tempdir/banners.txt
if ! [ $target_type = "net" ] ; then
echo '' ; f_Long; echo "BANNERS" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; fi ; sed '1,2d' $tempdir/banners.txt
if [ $target_type = "default" ] ; then
http80_server=$(jq -r '.http80.server' $tempdir/banners.json | sed '/null/d')
http80_title=$(jq -r '.http80.title' $tempdir/banners.json | sed '/null/d')
https_server=$(jq -r '.https443.server' $tempdir/banners.json | sed '/null/d')
https_cn=$(jq -r '.https443.cn' $tempdir/banners.json | sed '/null/d')
if [ -n "$http80_server" ] || [ -n "http80_title" ] ; then
echo "$http80_server" >> $tempdir/http; echo "$http80_title" >> $tempdir/http ; fi
if [ -n "$https_server" ] || [ -n "$https_cn" ] ; then
echo "$https_server" >> $tempdir/http; echo "$https_cn" >> $tempdir/http ; fi ; fi
}
f_NPING_OUT(){
cat $tempdir/np | sed '/Starting Nping/d' | sed '/Starting Nping/d' | sed '/Nping done:/d' | sed '/SENT/{x;p;x;}' |
sed '/RCVD/{x;p;x;}' | sed 's/s)/s)\n/g' | sed '/rtt:/{x;p;x;G}'
}
f_pubIP_HEADER(){
curl -s "http://ip-api.com/json/?fields=54537985" > $tempdir/local.json
offset=$(($(jq -r '.offset' $tempdir/local.json) / 3600)); org=$(jq -r '.org' $tempdir/local.json)
asn=$(jq -r '.as' $tempdir/local.json | cut -d ' ' -f 1 | sed 's/^*//' | sed 's/AS/AS /')
loc=$(jq -r '.country' $tempdir/local.json)
if [ -n "$curl_ua" ] ; then
ua_out="($ua_moz)" ; else
ua_out="(curl default)" ; fi
echo -e "\nUser Agent:  $(curl -V | head -1 | cut -d ' ' -f -2) $ua_out"
echo -e "\nPublic IP:   $(jq -r '.query' $tempdir/local.json) ($asn) | Geo: $loc (UTC $offset h)\n"
}
f_www_test_HEADER(){
echo -e "\n"; f_Long
if  [ $option_www = "1" ] ; then
headline="WEB SERVER HEALTH CHECK"
elif [ $option_www = "2" ] ; then
headline="WEB SERVER HEALTH - & VULNERS CHECK"
elif [ $option_www = "4" ] ; then
headline="WEBSITE OVERVIEW"; else
headline="WEB SERVER TESTING"; fi
echo "[+]  $headline | UTC: $(date --utc)" ; f_Long; f_pubIP_HEADER
}
f_HASHES_OUT(){
local s="$*"; echo ''; f_Long; echo -e "WEBSITE HASHES $(date)\n"; f_pubIP_HEADER; f_Long
echo -e "$s" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; cat $tempdir/web_hashes
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

#********************** HOST INFORMATION ***********************
f_geoWHOIS(){
local s="$*" ; as='' ; pfx=''; resource=''
f_getRIR "${s}"
if [ -n "$rir" ]; then
curl -s -m 5 "http://ip-api.com/json/${s}?fields=54750987" > $tempdir/geo.json
curl -s "https://stat.ripe.net/data/network-info/data.json?resource=${s}" > $tempdir/net.json
as=$(jq -r '.data.asns[0]?' $tempdir/net.json | sed '/null/d'); export as
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
timeout 7 whois -h whois.ripe.net -- "--no-personal $s" > $tempdir/whois ; fi; fi; else
timeout 7 whois -h whois.$rir.net -- "--no-personal $s" > $tempdir/whois; fi
if [[ $(grep -sEio "^netname:|^na:|^inetrev:" $tempdir/whois | wc -w) = 0 ]] ; then
timeout 10 whois -h whois.pwhois.org type=all $s > $tempdir/whois; fi; fi
}
f_ABUSE_C(){
local s="$*" ; netname='' ; range='' ; abx='' ; net_ip=$(echo $s | cut -d '/' -f 1)
netname=$(grep -E -a -i -m 1 "^netname:|^Net-Name:|^na:|^inetrev" $tempdir/whois | cut -d ':' -f 2- | sed 's/^ *//')
range=$(grep -E -a -i -m 1 "^inetnum|^inet6num:|^netrange:|^net-range|^in:|^i6:" $tempdir/whois | cut -d ' ' -f 2- | sed 's/^ *//')
ctry=$(grep -E -a -i -m 1 "^country:|^cy:" $tempdir/whois | cut -d ':' -f 2- | sed 's/^ *//' | tr [:lower:] [:upper:])
if [ $rir = "lacnic" ] ; then
abx=$(grep -E -a -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/whois | head -2 | sort -u | tr '[:space:]' ' ')
echo -e "[@]:  $abx |  NET:  $range" ; else
abx=$(grep -E -a -s -m 1 "^OrgAbuseEmail:|^% Abuse|^abuse-mailbox:|^e-mail:|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/whois |
grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b")
if [ -z "$abx" ] ; then
abx=$(grep -E -a -o -m 1 "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/whois); fi
for ax in $(echo "$abx" | awk -F'@' '{print $2}' | tr -d ' ' | sort -u); do
if echo $ax | grep -q -E "\.edu\.|\.co\.|\.org.|\.gov\."; then
echo $ax | cut -d '/' -f 1 | rev | cut -d '.' -f 1,2,3 | rev >> $tempdir/host_domains; else
echo $ax | cut -d '/' -f 1 | rev | cut -d '.' -f 1,2 | rev >> $tempdir/host_domains; fi; done
if [ $rir = "arin" ] ; then
if [[ $(grep -E "^CIDR:" $tempdir/whois | head -1 | wc -w) -lt 5 ]]; then
range_out=$(grep -E "^CIDR:" $tempdir/whois | head -1 | cut -d ' ' -f 2- | sed 's/^ *//'); else
range_out="$range"; fi ; else
if ! [[ ${net_ip} =~ $REGEX_IP4 ]] ; then
range_out="$range"; else
range_trimmed=$(echo $range | tr -d ' '); net_cidr=$(ipcalc -r ${range_trimmed} | sed '/deaggregate/d' | sed '/^$/d' | tr '[:space:]' ' '; echo '')
if [[ $(echo "$net_cidr" | wc -w) -lt 3 ]]; then
range_out="$net_cidr" ; else
range_out="$range"; fi ; fi; fi
if [ -n "$abx" ] ; then
echo -e "[@]:  $abx  |  $netname ($ctry): $range_out" ; else
echo -e "NET:  $netname ($ctry): $range_out" ; fi ; fi; echo -e "____\n" ; export abx; export range_out
}
f_v6INFO(){
local s="$*"
ipv6_info=$(${PATH_nmap} -6 -sn -Pn $s --script address-info.nse 2>/dev/null | grep -E -A 1 "\||\|_|ISATAP" | sed '/--/d' | sed '/address-info:/d' |
tr -d '|_' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' | sed 's/MAC address:/MAC/' | tr '[:space:]' ' '; echo '')
if [ -n "$PATH_sipcalc" ]; then
addr_type=$(${PATH_sipcalc} ${s} | grep -E "^Address type" | cut -d '-' -f 2- | sed 's/Addresses/Address/' | sed 's/^[ \t]*//;s/[ \t]*$//')
echo -e "\nIPv6 Info:   $addr_type"
if [ -n "$ipv6_info" ]; then
echo -e "\n             $ipv6_info\n"; fi; else
if [ -n "$ipv6_info" ]; then
echo -e "\nIPv6-Info:   $ipv6_info"; fi; fi
}
f_hostINFO(){
local s="$*"; orgname=''; isp=$(jq -r '.isp' $tempdir/geo.json)
if [ -n "$rir" ]; then
if ! [ $target_type = "hop" ]; then
offset=$(($(jq -r '.offset' $tempdir/geo.json) / 3600)); regio=$(jq -r '.regionName' $tempdir/geo.json)
echo -e "\nGeo:         $regio, $(jq -r '.country' $tempdir/geo.json) (UTC ${offset}h)" ; fi
if [ $target_type = "dnsrec" ] && [ $domain_enum = "false" ]; then
echo -e "\nISP:         $isp"; fi
if [ $target_type = "hop" ] || [ $target_type = "other" ]; then
isp=$(jq -r '.isp' $tempdir/geo.json); hosting=$(jq -r '.hosting' $tempdir/geo.json)
if [ $hosting = "true" ]; then
hosting_addr="(Hosting: $hosting)"; else
hosting_addr=''; fi; echo -e "\nISP:         $isp  $hosting_addr"; fi
if ! [[ ${s} =~ $REGEX_IP4 ]] ; then
f_v6INFO "${s}"; fi; f_getORGNAME "$tempdir/whois"
if [ $target_type = "hop" ] || [ $target_type = "other" ]; then
if [[ ${s} =~ $REGEX_IP4 ]]; then
echo ''; f_Long; echo -e "IP REPUTATION\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
f_IP_REPUTATION "${s}"; fi
if [ -f $tempdir/prefix_status ]; then
echo ''; cat $tempdir/prefix_status; fi; else
pfx=$(jq -r '.data.prefix' $tempdir/net.json)
if [ $domain_enum = "true" ] && ! [[ ${s} =~ $REGEX_IP4 ]] ; then
echo $pfx >> $tempdir/v6_prefixes; fi
asorg=$(curl -s -m 5 "https://stat.ripe.net/data/as-overview/data.json?resource=AS${as}" | jq -r '.data.holder')
if [ $domain_enum = "true" ] && [ $target_type = "dnsrec" ]; then
echo -e "\nPrefix:      $pfx | AS $as - $asorg"; else
rpki_status=$(curl -m 5 -s "https://stat.ripe.net/data/rpki-validation/data.json?resource=$as&prefix=$pfx" | jq -r '.data.status')
echo -e "\nPrefix:      $pfx | ROA: $rpki_status | AS $as - $asorg"; fi; fi
if [ $target_type = "other" ]; then
if [ $option_trace = "y" ] && [ $option_root = "y" ]; then
f_MTR "${s}"
elif [ $option_trace = "y" ] && [ $option_root = "n" ]; then
f_TRACEPATH "${s}"; fi; fi; fi
}
f_WEB(){
local s="$*"; f_BOGON "${s}"
if [ $bogon = "TRUE" ] ; then
echo ''; f_Long; echo "[+] $s | BOGON ADDRESS DETECTED | PREFIX: $bogon_prefix"; f_Long; echo ''; else
f_geoWHOIS "${s}"; geo_cc=$(jq -r '.countryCode' $tempdir/geo.json); cloud_service=''; hosting=$(jq -r '.hosting' $tempdir/geo.json)
if [ $target_type = "other" ]; then
mobile=$(jq -r '.mobile' $tempdir/geo.json)
if [ $mobile = "true" ]; then
mobile_addr="MOBILE ADDRESS |"; else
mobile_addr=''; fi
if [ -n "$as" ]; then
pfx=$(jq -r '.data.prefix' $tempdir/net.json); f_PREFIX "${pfx}" > $tempdir/prefix_status; fi; else
mobile_addr=''; fi
if [[ ${s} =~ $REGEX_IP4 ]] ; then
if [ $domain_enum = "true" ] || [ $target_type = "other" ]; then
curl -s "https://isc.sans.edu/api/ip/${s}?json" > $tempdir/iscip.json; ip_num=$(jq -r '.ip.number?' $tempdir/iscip.json)
if [ $domain_enum = "true" ]; then
f_threatSUMMARY "${s}" >> $tempdir/isc; fi
if [ -n "$ip_num" ] ; then
cloud_service=$(jq -r '.ip.cloud?' $tempdir/iscip.json | sed '/null/d'); fi
if [ -n "$cloud_service" ] ; then
housing="Cloud:  $cloud_service" ; else
housing="Hosting:  $hosting" ; fi
echo ''; f_Long; echo "[+]  $s  | $geo_cc | AS $as | $mobile_addr $housing"; f_Long; fi; else
echo ''; f_Long; echo "[+]  $s  | $geo_cc | AS $as |  Hosting:  $hosting"; f_Long; fi; f_ABUSE_C "${s}" ; f_hostINFO "${s}"; fi
}
f_HOP(){
local s="$*"; echo ''; f_Long
f_BOGON "${s}"
if [ $bogon = "TRUE" ] ; then
echo "HOP - $s | BOGON ADDRESS DETECTED | PREFIX: $bogon_prefix"; f_Long; else
f_geoWHOIS "${s}"
mobile=$(jq -r '.mobile' $tempdir/geo.json)
if [ $mobile = "true" ]; then
mobile_addr="| MOBILE !"; else
mobile_addr=''; fi
if [ -n "$rir" ]; then
rir_caps=$(echo $rir | tr [:lower:] [:upper:])
if [[ ${s} =~ $REGEX_IP4 ]] ; then
netrange=$(grep -E "^inetnum:|^netrange:" $tempdir/whois | cut -d ':' -f 2- | sed 's/^ *//' | tr -d ' ')
cidr=$(ipcalc ${netrange} | tail -1); else
cidr=$(grep -E "^inet6num:|^CIDR:" $tempdir/whois | awk '{print $NF}' | sed 's/^ *//' | tr -d ' '); fi
if [ -n "$as" ]; then
pfx=$(jq -r '.data.prefix' $tempdir/net.json); f_PREFIX "${pfx}" > $tempdir/prefix_status; geo_cc=$(jq -r '.countryCode' $tempdir/geo.json)
offset=$(($(jq -r '.offset' $tempdir/geo.json) / 3600)); regio=$(jq -r '.regionName' $tempdir/geo.json)
if [[ ${s} =~ $REGEX_IP4 ]]; then
echo "HOP |  $s  | $geo_cc | $rir_caps | AS $as |  ROA: $(jq -r '.data.status' $tempdir/rpki.json)  |  $(f_TOR1 "${s}") $mobile_addr "; else
echo "HOP |  $s  |  $geo_cc  |  $rir_caps  |  AS $as  |  ROA: $(jq -r '.data.status' $tempdir/rpki.json)  $mobile_addr "; fi; f_Long
f_ABUSE_C "${s}"; echo -e "\nGeo:         $regio, $(jq -r '.country' $tempdir/geo.json) (UTC ${offset}h)"; f_hostINFO "${s}"; else
if [[ $(grep -sEco "$cidr" $tempdir/ix_pfx) -gt 0 ]]; then
ixlid=$(grep -E -A 1 "$cidr" $tempdir/ix_pfx | tail -1 | tr -d ' ')
curl -s "https://www.peeringdb.com/api/ix/${ixlid}" > $tempdir/ixlan.json
ix_name=$(jq -r '.data[0].name' $tempdir/ixlan.json); ix_cc=$(jq -r '.data[0].org.country' $tempdir/ixlan.json)
ix_city=$(jq -r '.data[0].city' $tempdir/ixlan.json); ix_mail=$(jq -r '.data[0].tech_email' $tempdir/ixlan.json)
ix_phone=$(jq -r '.data[0].tech_phone' $tempdir/ixlan.json)
echo "HOP - IX |  $s  |  $ix_name  |  $ix_cc"; f_Long; f_ABUSE_C "${s}"
echo -e "\nGeo:         $ix_city, $ix_cc"; echo -e "\nContact:     $ix_mail  $ix_phone\n"; f_hostINFO "${s}"; else
echo "HOP | $s"; f_Long; f_ABUSE_C "${s}"; f_hostINFO "${s}"; fi; fi; fi; fi; f_CLEANUP_FILES
}
f_providerINFO(){
local s="$*"; domain_addr=$(dig @anycast.censurfridns.dk a +short $s | head -1)
if [ -n "$domain_addr" ]; then
echo -e "DOMAIN HOST:\n"; curl -s -m 5 "http://ip-api.com/json/${domain_addr}?fields=61439" > $tempdir/geo.json
geo=$(jq -r '.country' $tempdir/geo.json); regio=$(jq -r '.regionName' $tempdir/geo.json)
org=$(jq -r '.org' $tempdir/geo.json); isp=$(jq -r '.isp' $tempdir/geo.json); query=$(jq -r '.query' $tempdir/geo.json)
if [ -n "$org" ] ; then
org_out="$org"; else
org_out="$isp"; fi
reverse=$(echo $domain_addr | awk -F'.' '{printf $4 "." $3 "." $2 "." $1}')
abx=$(dig +short $reverse.abuse-contacts.abusix.zone txt | tr -d '/"'| sed 's/^ *//' | tr '[:space:]' ' '; echo '')
echo -e "$query | $regio, $geo | $org_out | $abx\n"; fi
echo -e "\nSSL:"; curl -s "https://api.certspotter.com/v1/issuances?domain=${s}&expand=dns_names&expand=issuer" > $tempdir/certs.json
csp_resp=$(jq -r '.[] | {Subject: .dns_names[], Issuer: .issuer.name, NotBefore: .not_before, NotAfter: .not_after}' $tempdir/certs.json | tr -d '}",{' |
sed 's/^ *//' | sed '/^$/d' | grep -E -m 2 -A 3 "Subject: ${s}" | sed 's/--//g' | sed '/^$/d' | sed 's/Subject:/\nSubject:  /g' |
sed 's/Issuer:/Issuer:   /g' | sed 's/NotAfter:/NotAfter: /g' | fmt -s -w 80)
if [ -n "$csp_resp" ]; then
echo "$csp_resp"; else
echo -e "\ncertspotter.com: No results for $s"; fi; echo ''
}
f_hop_asINFO(){
echo ''; f_Long; echo "[+] ASNs"; for a in $(cat $tempdir/asns | sort -ug); do
f_AS_SUMMARY "${a}"; done; rm $tempdir/asns
if [ -f $tempdir/host_domains ]; then
echo ''; f_Long; echo -e "[+] SERVICE PROVIDER DOMAINS"; isp_domains=$(cat $tempdir/host_domains | sort -u)
for d in $isp_domains; do
f_Long; echo -e "$d\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; f_whoisSTATUS "${d}"; f_providerINFO "${d}"; echo ''; done; rm $tempdir/host_domains; fi
}
f_recordINFO(){
local s="$*"; f_BOGON "${s}"
if [ $bogon = "TRUE" ] ; then
echo ''; f_Long; echo "[+] $s | BOGON ADDRESS DETECTED | PREFIX: $bogon_prefix"; f_Long; echo ''; else
f_geoWHOIS "${s}" ; cloud_service=''; hosting=$(jq -r '.hosting' $tempdir/geo.json)
if ! [[ ${s} =~ $REGEX_IP4 ]] ; then
housing="| Hosting: $hosting"; else
if [ $domain_enum = "true" ] || [ $option_bl="y" ] ; then
curl -s "https://isc.sans.edu/api/ip/${s}?json" > $tempdir/iscip.json; f_threatSUMMARY "${s}" >> $tempdir/isc
ip_num=$(jq -r '.ip.number?' $tempdir/iscip.json)
if [ -n "$ip_num" ] ; then
cloud_service=$(jq -r '.ip.cloud?' $tempdir/iscip.json | sed '/null/d'); else
cloud_service=''; fi
if [ -n "$cloud_service" ] ; then
housing="| Cloud:  $cloud_service" ; else
housing="| Hosting:  $hosting" ; fi ; else
housing="| Hosting: $hosting"; fi; fi
if [[ $(echo "$record_nme" | wc -w) -gt 1 ]]; then
f_Long; echo "$record_type | $record_ip $housing"; echo -e "\n$record_nme"; f_Long; else
f_Long; echo "$record_type | $record_ip $housing | $record_nme" ; f_Long; fi
f_ABUSE_C "${s}"; f_hostINFO "${s}"; echo ''; fi
}
f_hostDEFAULT(){
echo ''; local s="$*"; f_BOGON "${s}"
if [ $bogon = "TRUE" ] ; then
f_Long; echo "ERROR - BOGON ADDRESS DETECTED  -  192.168.178.23  ($bogon_prefix)"; f_Long; echo ''; else
orgname='' ; assign=''; suballoc=''; resource=''; parent=''; f_geoWHOIS "${s}"
if [ -n "$rir" ]; then
pfx=$(jq -r '.data.prefix' $tempdir/net.json)
regio=$(jq -r '.regionName' $tempdir/geo.json); offset=$(($(jq -r '.offset' $tempdir/geo.json) / 3600))
org=$(jq -r '.org' $tempdir/geo.json); isp=$(jq -r '.isp' $tempdir/geo.json); whois_reg=$(echo $rir | tr [:lower:] [:upper:])
hosting=$(jq -r '.hosting' $tempdir/geo.json); mobile=$(jq -r '.mobile' $tempdir/geo.json); geo_cc=$(jq -r '.countryCode' $tempdir/geo.json)
f_Long; echo "[+] $s | $geo_cc | $whois_reg | AS $as "; f_Long; f_ABUSE_C "${s}"
echo -e "\nGeo:         $regio, $(jq -r '.country' $tempdir/geo.json) (UTC ${offset}h)"
if ! [[ ${s} =~ $REGEX_IP4 ]]; then
f_v6INFO "${s}"
echo -e "\nISP:         $isp | Hosting: $hosting"; else
echo -e "\nISP:         $isp"; echo -e "\n             Mobile: $mobile | $(f_TOR1 "${s}") | Hosting: $hosting"; fi
if ! [ $rir = "lacnic" ]; then
f_getORGNAME "$tempdir/whois"; fi; echo ''
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
if  [ $option_bl = "y" ] && [[ ${s} =~ $REGEX_IP4 ]]; then
f_Long; echo -e "IP REPUTATION\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' ; f_IP_REPUTATION "${s}" ; echo '' ; fi
if [ $rir = "lacnic" ] ; then
echo '' ; f_lacnicWHOIS "${s}" ; else
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
if ! [ "$allocation" = "$resource" ]; then
echo '' ; f_Long ; echo -e "NETWORK" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; fi
if [ "$resource" = "$suballoc" ] || [ "$resource" = "$assign" ] ; then
created=$(grep -E -i -m 1 "^created:|^RegDate:" $tempdir/whois | grep -E -o "[0-9]{4}-[0-9]{2}-[0-9]{2}")
netrange=$(grep -E "^inetnum:|^inet6num:" $tempdir/whois | cut -d ':' -f 2- | sed 's/^ *//' | head -1)
cc=$(grep -E "^country:" $tempdir/whois | awk '{print $NF}' | tr -d ' ' | head -1)
de=$(grep -E "^descr:" $tempdir/whois | cut -d ':' -f 2- | sed 's/^ *//' | head -1)
echo -e "\nNet:         $n_name | $n_address | $n_status"; echo -e "\n             $created, $cc (RIPE)"; fi
if [ -n "$de" ] ; then
echo -e "\nDescr:       $de" ; fi
echo '' ; f_Long ; echo -e "NETWORK" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
if [ $rir = "ripe" ] && [[ ${s} =~ $REGEX_IP4 ]] ; then
if [ -n "$parent" ] ; then
whois -h whois.ripe.net -- "--no-personal $parent" > $tempdir/whois; f_netSUM "${parent}"
elif ! [ "$resource" = "$allocation" ] ; then
whois -h whois.ripe.net -- "--no-personal $allocation" > $tempdir/whois ; f_netSUM "${allocation}" ;else
f_netSUM "${resource}"; fi ; fi ; else
echo '' ; f_Long ; echo -e "NETWORK" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
f_netSUM "${s}" ; fi; echo '' ; f_ORG "$tempdir/whois"
if ! [ $rir = "arin" ] ; then
if ! [ $rir = "ripe" ] || ! [[ ${s} =~ $REGEX_IP4 ]] ; then
ac=$(grep -E "^admin-c:" $tempdir/whois | cut -d ':' -f 2- | sed 's/^ *//' | head -1) ;fi
echo '' ; f_Long; f_ADMIN_C "${ac}"; fi
echo '' ; f_PREFIX "${pfx}"; fi; fi; fi
}
f_webSHORT(){
local s="$*"
f_BOGON "${s}"
if [ $bogon = "TRUE" ] ; then
echo ''; f_Long; echo "[+] $s | BOGON ADDRESS DETECTED | PREFIX: $bogon_prefix"; f_Long; echo ''; else
curl -s -m 5 "http://ip-api.com/json/${s}?fields=33581577" > $tempdir/geo.json; geo=$(jq -r '.country' $tempdir/geo.json)
regio=$(jq -r '.regionName' $tempdir/geo.json); offset=$(($(jq -r '.offset' $tempdir/geo.json) / 3600))
isp=$(jq -r '.isp' $tempdir/geo.json); ipaddr=$(jq -r '.query' $tempdir/geo.json)
curl -s "https://stat.ripe.net/data/network-info/data.json?resource=${s}" > $tempdir/net.json
if [[ ${s} =~ $REGEX_IP4 ]] ; then
v6_info=''; reverse=$(echo $s | awk -F'.' '{printf $4 "." $3 "." $2 "." $1}')
abx=$(dig +short $reverse.abuse-contacts.abusix.zone txt | tr -d '/"'| sed 's/^ *//' | tr '[:space:]' ' ' | sed 's/,/ /g'; echo ''); else
v6_info=$(${PATH_nmap} -6 -sn -Pn $s --script address-info.nse 2>/dev/null | grep -E -A 1 "\||\|_|ISATAP" | sed '/--/d' | sed '/address-info:/d' |
tr -d '|_' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' | sed 's/MAC address:/MAC/' | tr '[:space:]' ' '; echo '')
abx=$(dig txt +short $(host $s | awk '{print $1}' | sed 's/.ip6.arpa//').abuse-contacts.abusix.zone | tr -d '"' | sed 's/^ *//' | tr '[:space:]' ' ' |
sed 's/,/ /g'; echo '')
nibble=$(host $s | sed 's/Host //' | cut -d ' ' -f 1 | sed 's/.ip6.arpa//' | tr -d ' ')
abx=$(dig +short ${nibble}.abuse-contacts.abusix.zone txt | tr -d '\"' | sed 's/^ *//' | tr '[:space:]' ' ' | sed 's/,/ /g'; echo ''); fi
f_Long; echo -e "$s\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
echo "GEO:       $regio, $geo  (UTC $offset)"
echo "ISP:       $isp"
echo "[@]:       $abx"
if [[ ${s} =~ $REGEX_IP4 ]] && [ $bl_check = "true" ]; then
echo -e "\nIP REPUTATION\n\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
f_IP_REPUTATION "${s}"; echo ''; else
if [ -n "$v6_info" ]; then
echo "IPV6 INFO: $v6_info";fi; fi; jq -r '.data.prefix' $tempdir/net.json >> $tempdir/prefixes.list; fi; echo ''
}
f_nsSHORT(){
local s="$*"; echo ''; curl -s -m 5 --location --request GET "https://stat.ripe.net/data/dns-chain/data.json?resource=$s" > $tempdir/chain.json
jq -r '.data.forward_nodes' $tempdir/chain.json | tr -d '}[,"{' | sed 's/^ *//' | sed '/^$/d' | sed 's/\]//g'
echo -e "AUTH NS:\n"
jq -r '.data.authoritative_nameservers[]?' $tempdir/chain.json | sort -V | tr '[:space:]' ' ' | fmt -s -w 80; echo ''
if ! [ $option_connect = "0" ]; then
bindvers=$(dig @${s} version.bind txt chaos +norecurse +noedns +short | tr -d '"' | sed 's/^ *//' |
sed 's/;; connection timed out; no servers could be reached/connection timed out/g' | grep -E -v "^;|^;;" | sed '/^$/d')
if [ -n "$bindvers" ] ; then
echo -e "\n\nVERSION.BIND\n" ; echo -e "\t\t\t$bindvers" ; fi; fi
target_ipv4=$(host -t a $s | grep "has address" | awk '{print $NF}' | sort -uV)
target_ipv6=$(host -t aaaa $s | grep "has IPv6 address" | awk '{print $NF}' | sort -uV); echo ''
if [ -n "$target_ipv4" ] ; then
for a in $target_ipv4 ; do
f_hostSHORT "${a}"; done; fi
if [ -n "$target_ipv6" ] ; then
for z in $target_ipv6 ; do
f_hostSHORT "${z}"; done; fi
}
f_hostSHORT(){
local s="$*" ; curl -s "http://ip-api.com/json/${s}?fields=37773569" > $tempdir/geo.json
curl -s -m 5 "http://ip-api.com/json/${s}?fields=37775361" > $tempdir/geo.json
ipaddr=$(jq -r '.query' $tempdir/geo.json); geo=$(jq -r '.country' $tempdir/geo.json)
offset=$(($(jq -r '.offset' $tempdir/geo.json) / 3600)); asname=$(jq -r '.asname' $tempdir/geo.json)
as_org=$(jq -r '.as' $tempdir/geo.json | cut -d ' ' -f 2- | sed 's/^ *//')
curl -s "https://stat.ripe.net/data/network-info/data.json?resource=${ipaddr}" > $tempdir/net.json
autn=$(jq -r '.data.asns[0]' $tempdir/net.json); pfx=$(jq -r '.data.prefix' $tempdir/net.json)
as_out="AS $autn $asname - $as_org"
if [[ ${ipaddr} =~ $REGEX_IP4 ]] ; then
v6_info=''; reverse=$(echo $ipaddr | awk -F'.' '{printf $4 "." $3 "." $2 "." $1}')
abx=$(dig +short $reverse.abuse-contacts.abusix.zone txt | tr -d '/"'| sed 's/^ *//' | tr '[:space:]' ' '; echo ''); else
v6_info=$(${PATH_nmap} -6 -sn -Pn $s --script address-info.nse 2>/dev/null | grep -E -A 1 "\||\|_|ISATAP" | sed '/--/d' | sed '/address-info:/d' |
tr -d '|_' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' | sed 's/MAC address:/MAC/' | tr '[:space:]' ' '; echo '')
nibble=$(host $s | sed 's/Host //' | cut -d ' ' -f 1 | sed 's/.ip6.arpa//' | tr -d ' ')
abx=$(dig +short ${nibble}.abuse-contacts.abusix.zone txt | tr -d '\"' | sed 's/^ *//' | tr '[:space:]' ' ' | sed 's/,/ /g'; echo ''); fi
echo -e "\n$ipaddr | $geo (UTC $offset)"
if [ -n "$v6_info" ]; then
echo -e "\n$v6_info"; fi
if [ -n "$abx" ]; then
echo -e "\n$abx" | sed 's/,/ /g'; fi
echo -e "\n$pfx | $as_out\n"
}

#********************** WEB SERVER / WEBSITE - STATUS, PAGE DUMP, MTR, PAGE LOADING TIMES, CDN & LOAD BALANCING DETECTION ***********************
f_writeOUT(){
local s="$*" ; curl -m 10 ${curl_array[@]} ${curl_ua} ${s} 2>$tempdir/curl -D $tempdir/headers -o $tempdir/page.html -w \
"
URL:             %{url_effective}
IP:              %{remote_ip}
Status:          HTTP %{http_version} %{response_code}  (%{remote_ip})
Time Total:      %{time_total} s
" > $tempdir/response
cat $tempdir/page.html | sed 's/\\n/ /g' | sed 's/\\r/ /g' | tr -d '\\' | sed 's/ = /=/g' | sed 's/= /=/g' | sed 's/ = /=/g' |
sed 's/= /=/g' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' | sed 's/<meta/\n\n<meta/g' | sed 's/<script/\n\n\n<script/g' |
sed 's/<!--/\n\n<!--/g' | sed 's/<\/script>/<\/script>\n\n\n/g' | sed 's/<noscript/\n\n<noscript/g' | sed 's/<\/noscript>/<\/noscript>\n\n/g' |
sed 's/<\/head>/<\/head>\n\n/' | sed 's/<main/\n\n<main/' | sed 's/<article/\n\n<article/g' | sed 's/<div/\n\n<div/g' | tr "\'" '\"'  > $tempdir/page_src
cat $tempdir/page_src | tr -d '\"' |  sed 's/ = /=/g' | sed 's/= /=/g' | tr [:upper:] [:lower:] > $tempdir/no_quotes
grep -E -A 6 "<script" $tempdir/page_src | sed '/^$/d' | tr [:upper:] [:lower:] | tee $tempdir/cms > $tempdir/src_scripts
sed 's/<link=/\n\n<link=/g' $tempdir/page_src | tr [:upper:] [:lower:] | grep 'link' | tee -a $tempdir/cms > $tempdir/page_links
grep -A 7 '<!--' $tempdir/page_src | tee -a $tempdir/cms  > $tempdir/comments
sed -n '/<head/,/<\/head>/p' $tempdir/page_src >> $tempdir/cms ; cat $tempdir/headers >> $tempdir/cms
cat $tempdir/curl | tr -d '<*>' | sed 's/^ *//' > $tempdir/curl_trimmed
if [ $report = "true" ] && [ $domain_enum = "true" ] ; then
cat $tempdir/page.html > $outdir/SOURCE.${s}.html; fi
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
TCP Handshake:  %{time_connect} s
SSL Handshake:  %{time_appconnect} s
Total Time:  %{time_total} s
" > $tempdir/status_raw
p2_sha1=$(sha1sum $tempdir/p2.html | cut -d ' ' -f 1); timestamp_utc=$(date -u +"%T  %a %b %d %Y"); timestamp=$(date)
grep -E "^URL:|^IP:|^Status:|^Resp.Times:" $tempdir/status_raw | sed 's/DNS:/ | DNS:/g' | sed 's/SSL:/ | SSL:/g' | sed '/^$/d' |
sed '/Status:/G' > $tempdir/status.txt
cat $tempdir/stat | cut -d ' ' -f 3- | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' | sed 's/server:/Server:/g' | sed 's/via:/Via:/g' |
sed 's/cache-control:/Cache-Control:/g' | sed 's/Cache-control/Cache-Control:/g' > $tempdir/stat_trimmed
eff_url=$(grep -E "^URL:" $tempdir/status_raw | awk '{print $NF}' | sed 's/^[ \t]*//;s/[ \t]*$//' | tr -d ' ')
eff_ip=$(grep -E "^IP:"  $tempdir/status_raw | awk '{print $NF}' | sed 's/^[ \t]*//;s/[ \t]*$//' | tr -d ' ')
status=$(grep -E "^st:" $tempdir/status_raw | cut -d ':' -f 2- | sed 's/^ *//' | sed 's/HTTP /HTTP\//')
redir=$(grep -E "^rd:" $tempdir/status_raw | awk '{print $NF}' | tr -d ' ')
user_agent=$(grep -i 'user-agent:' $tempdir/stat_trimmed | tail -1 | cut -d ':' -f 2- | sed 's/^ *//')
httpserv=$(grep -E -i "^Server:" $tempdir/h2 | cut -d ':' -f 2 | sed 's/^[ \t]*//;s/[ \t]*$//' | tail -1)
endpoint=$(grep 'Connected to' $tempdir/stat_trimmed | tail -1 | awk '{print $3,$4,$5,$6}' | sed 's/ port /:/')
echo -e "\nHost:      $eff_ip  (Status: $(echo $status | awk '{print $NF}'))" >> $tempdir/hashes_temp
echo -e "\nHost:      $eff_ip" >> $tempdir/web_hashes
echo -e "\nURL:       $eff_url | Status: $(echo $status | awk '{print $NF}')" >> $tempdir/web_hashes
f_TITLE "$tempdir/p2.html" | sed 's/Title:          /Title:     /' >> $tempdir/web_hashes; echo '' >> $tempdir/web_hashes
echo -e "\nUTC:       $timestamp_utc" | tee -a $tempdir/hashes_temp >> $tempdir/web_hashes
echo -e "\nSHA1:      $p2_sha1\n" | tee -a $tempdir/hashes_temp >> $tempdir/web_hashes
if [ $handshake_details = "true" ]; then
echo '' | tee $tempdir/writeout > $tempdir/HANDSHAKE.txt; f_Long | tee -a $tempdir/writeout >> $tempdir/HANDSHAKE.txt
echo -e "[+] $target [$s] | SSL HANDSHAKE" | tee -a $tempdir/writeout >> $tempdir/HANDSHAKE.txt
f_Long | tee -a $tempdir/writeout >> $tempdir/HANDSHAKE.txt; echo '' | tee -a $tempdir/writeout >> $tempdir/HANDSHAKE.txt
echo -e "SystemTime:    $(date)" >> $tempdir/HANDSHAKE.txt; echo -e "User Agent:    $user_agent\n" >> $tempdir/HANDSHAKE.txt
cat $tempdir/status.txt | tee -a $tempdir/writeout >> $tempdir/HANDSHAKE.txt
f_curlHandshake | tee -a $tempdir/writeout >> $tempdir/HANDSHAKE.txt; cat $tempdir/HANDSHAKE.txt >> ${outdir}/CURL_write_out.${target}.txt
cat $tempdir/writeout >> $tempdir/writeout.${target}.txt; fi
echo '' ; f_Long; echo "[+] SERV. INSTANCE |  $s  | STATUS: $(echo $status | awk '{print $NF}')" ; f_Long
echo -e "\nRequest:        $target ($s)" ; echo -e "\nEndpoint:       $endpoint"
if [ $domain_enum = "false" ]; then
echo ''; fi
echo -e "\nStatus:         $status,  redirects: $redir"; f_detectCDN "$tempdir/h2"
if [ $domain_enum = "false" ]; then
f_TITLE "$tempdir/p2.html"; echo ''; fi
if [[ $(cat $tempdir/ips_all | sort -u | wc -w) -gt 1 ]]; then
echo -e "Website SHA1:   $p2_sha1\n"; else
f_Long; echo -e "Website SHA1:   $p2_sha1"; echo -e "\n                ($timestamp)"; fi
t_dns=$(grep -E "^DNS Lookup:" $tempdir/status_raw  | sed 's/^[ \t]*//;s/[ \t]*$//')
t_tcp=$(grep -E "^TCP Handshake:"  $tempdir/status_raw | sed 's/^[ \t]*//;s/[ \t]*$//')
t_ssl=$(grep -E "^SSL Handshake:"  $tempdir/status_raw | sed 's/^[ \t]*//;s/[ \t]*$//')
t_total=$(grep -E "^Total Time:" $tempdir/status_raw | sed 's/^[ \t]*//;s/[ \t]*$//')
f_Long; echo -e "RESPONSE TIMES\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
echo -e "$t_tcp      $t_dns\n"; echo -e "$t_ssl      $t_total\n"
if [ $option_ping = "1" ]; then
f_PING "${s}"; echo ''; fi; f_inspectHEADERS "$tempdir/h2"; echo ''; f_REDIR; echo ''
}
f_REDIR(){
grep -E -i "^Connected to|^HTTP|^content-length:|^Server:|^SSL certificate verify|^via-proxy:|^via-squid:" $tempdir/stat_trimmed  |
sed 's/301 Moved Permanently/301/g' | sed 's/302 Found /302/g' | sed 's/200 OK /200/g' | sed 's/307 Temporary Redirect/307/g' |
sed 's/SSL certificate verify /|SSL: /g' | sed 's/SSL: ok./SSL: OK/g' | sed 's/Temporary //g' | sed 's/Permanent //g' | sed 's/Bad //g' |
sed 's/Request //g' | sed 's/Redirect//g' | sed 's/Forbidden //g' | sed 's/Temporarily//g' | sed 's/[Cc]ontent-[Ll]ength: /| content-length:/g' |
sed 's/result: unable to get local issuer certificate (20), continuing anyway./error/g' |
sed 's/) port /):/g' | sed 's/[Vv]ia-[Pp]roxy:/|via-proxy:/g' | sed 's/HTTP/| HTTP/g' | sed 's/[Vv]ia-[Ss]quid:/|via-squid:/g' |
sed 's/[Ss]erver:/|/g' | sed 's/Connected to //g' | sed 's/(#/##/g' | awk -F'##' '{print $2,$1}' | sed 's/^0)/%0)/g' |
sed 's/^1)/%1)/g' | sed 's/^2)/%2)/g' | sed 's/^3)/%3)/g' | sed 's/^4)/%4)/g' | tr '[:space:]' ' ' | sed 's/%0)/\n\n0)/g' |
sed 's/%1)/\n\n1)/g' | sed 's/%2)/\n\n2)/g' | sed 's/%3)/\n\n3)/g' | sed 's/%4)/\n\n4)/g' > $tempdir/redir
f_Long; echo -e "REDIRECTS" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
cat $tempdir/redir | tr -d ' ' | sed 's/|/ | /g' | sed 's/SSL:/SSL: /g' | sed 's/HTTP\/1.1/HTTP\/1.1 /g' | sed 's/HTTP\/1.2/HTTP\/1.2 /g' |
sed 's/HTTP\/2/HTTP\/2 /g' | sed 's/):/:/g' | sed 's/(/ | /g' | sed 's/)/) /g' | sed 's/squid:/squid: /g' | sed 's/proxy:/proxy: /g' |
sed 's/length:/length: /' | sed 's/200OK/200 OK/g' | fmt -s -w 120
}
f_PING(){
f_Long; echo -e "ROUND TRIP - TIMES (ms)\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
local s="$*" ; timeout 5 ping -q -c 4 $s > $tempdir/ipg
sent=$(grep '%' $tempdir/ipg | awk '{print $1}'); recvd=$(grep '%' $tempdir/ipg | awk -F',' '{print $2}' | awk '{print $1}')
loss=$(grep '%' $tempdir/ipg | awk -F',' '{print $3}' | awk '{print $1}')
icmp_rtt=$(grep 'rtt' $tempdir/ipg | tr -d 'ms' | awk -F'=' '{print $2}' | tr -d ' ' | awk -F'/' '{print "Min:",$1," Max:",$2," Avg:",$3}')
if [ -n ${PATH_httping} ]; then
if [[ ${s} =~ $REGEX_IP4 ]] ; then
${PATH_httping} -c 4 -t 5 ${s} > $tempdir/hpg; else
${PATH_httping} -6 -c 4 -t 5 ${s} > $tempdir/hpg; fi
http_connects=$(grep 'connects' $tempdir/hpg | cut -d ',' -f -4 | sed 's/^ *//')
http_rtt=$(grep 'round-trip' $tempdir/hpg | tr -d 'ms' | awk -F'=' '{print $2}' | tr -d ' ' |
awk -F'/' '{print "Min:",$1," Max:",$2," Avg:",$3}' | sed 's/^ *//')
if [[ ${s} =~ $REGEX_IP4 ]] ; then
${PATH_nping} --tcp-connect -p 80 -c 4 $s > $tempdir/npg; else
${PATH_nping} -6 --tcp-connect -p 80 -c 4 $s > $tempdir/npg; fi
tcp_loss=$(grep 'connection attempts' $tempdir/npg | awk -F ':' '{print $NF}')
tcp_connects=$(grep 'connection attempts' $tempdir/npg | cut -d '|' -f 1 | sed 's/TCP connection attempts:/Connects:/')
tcp_rtt=$(grep 'rtt:' $tempdir/npg | sed 's/ rtt:/:/g' | tr -d '|'); fi
if [ -n "$sent" ]; then
echo -e "\nICMP:  $sent sent, $recvd ok, $loss packet loss - $icmp_rtt"; else
echo -e "ICMP:  failed"; fi
if [ -n ${PATH_httping} ]; then
echo -e "\nHTTP:  $http_connects - $http_rtt"; else
echo -e "\nTCP:   $tcp_connects $tcp_loss - $tcp_rtt"; fi
}
f_requestTIME(){
local s="$*" ; f_Long
${PATH_nmap} -sT -p 443 -R --resolve-all --script http-chrono,https-redirect,http-title ${s} 2>/dev/null > $tempdir/chrono.txt
if [ -n "$target6" ] ; then
${PATH_nmap} -6 -sT -p 443 -R --resolve-all --script http-chrono,https-redirect,http-title ${s} 2>/dev/null >> $tempdir/chrono.txt ; fi
if ! [ "$s" = "$target_host" ]; then
if [ -n "$target_host4" ] ; then
${PATH_nmap} -sT -p 443 -R --resolve-all --script http-chrono,https-redirect,http-title $target_host 2>/dev/null >> $tempdir/chrono.txt; fi
if [ -n "$target_host6" ] ; then
${PATH_nmap} -sT -p 443 -R --resolve-all --script http-chrono,https-redirect,http-title $target_host 2>/dev/null >> $tempdir/chrono.txt; fi; fi
echo "PAGE LOADING & REFRESH TIMES (PORT: 443)" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
grep -E -i "Nmap scan report|http-chrono:|http-title:" $tempdir/chrono.txt | tr -d '|_' | sed 's/^ *//' | sed '/Nmap scan report/G' |
sed 's/http-chrono: //g' | sed 's/Request times for /\nPage:           /g' | sed 's/; avg:/\nTimes:          avg: /g' | sed '/Page/G' |
sed 's/Nmap scan report for/\n\n\nHost:          /g' | sed 's/;min:/; min: /g' | sed 's/;max:/; max: /g' | sed 's/http-title:/\nTitle:         /g'
echo ''; rm $tempdir/chrono.txt
}
f_PATH_MTU(){
grep -E "scan report|down|*./tcp|*./udp|\||\|_"  $tempdir/pmtu | tr -d '|_' | sed '/Nmap scan report/{x;p;x;G}' |
sed '/down/G' | sed 's/^ *//' | sed '/\/tcp /G'| sed '/\/udp /G' | sed '/PMTU/G' | sed 's/path-mtu:/Path-MTU: /g' |
sed 's/Nmap scan report for //g' | sed 's/^ *//g'; echo '' ; rm $tempdir/pmtu
}
f_MTR(){
local s="$*" ; echo ''; f_Long ; echo -e "$s  MTR ($mtr_info)\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
if [ $target_type = "hop" ]; then
sudo ${PATH_mtr} ${mtr_array[@]} -w -o "  L  D  A BW  M" ${s} | sed '/Start:/G' | sed '/Javg/G' > $tempdir/mtr.txt
cat $tempdir/mtr.txt; f_Shorter; echo -e "AVG = average RTT in ms; Wrst = worst RTT; \nJavg = average jitter"; else
sudo ${PATH_mtr} ${mtr_array[@]} -w -o "  L  D  A  M" ${s} | sed '/Start:/G' | sed '/Javg/G' > $tempdir/mtr.txt
cat $tempdir/mtr.txt; f_Shorter; echo -e "AVG = average RTT in ms; Javg = average jitter" ; fi; echo ''
}
f_MTR_HT(){
local s="$*"; f_Long; echo -e "$target\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; curl -s https://api.hackertarget.com/mtr/?q=${s}${api_key_ht} > $tempdir/mtr_ht
sed '/HOST:/{x;p;x;G}' $tempdir/mtr_ht ; echo -e "\n Source > hackertarget.com IP API\n"
}
f_TRACEPATH(){
local s="$*"; f_Long; echo "TRACEPATH" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; echo "$s"; echo -e "$(date)\n\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
${PATH_tracepath} ${path_args} $s | sed 's/^ *//' > $tempdir/trace; cat $tempdir/trace | sed '/Resume/i \\n___________________________________\n'; echo ''
}
#********************** HTTP HEADERS - DUMP & ANALYSIS ***********************
f_HEADERS(){
local s="$*" ; echo ''
if [ $option_connect = "0" ] ; then
curl -s -m 5 "https://api.hackertarget.com/httpheaders/?q=${s}${api_key_ht}" > $tempdir/headers; fi
f_Long ; echo -e "[+] $s | HTTP HEADERS | $(date)" ; f_Long ; echo ''
cat $tempdir/headers | sed 's/^ *//' | fmt -w 100 -s ; echo ''
}
f_detectCDN(){
local s="$*"; cdn=''
if grep -q -i -E "Server: AkamaiGHost|server: Akamai|server: AkamaiEdge|^x-akamai-transformed" ${s}; then
cdn="Akamai"
elif grep -q -i -E "^x-fastly-cache-status:|^fastly-restarts:" ${s}; then
cdn="Fastly"
elif grep -q -i -E "Server: Cloudflare|cf-ray:|cf-cache-status" ${s}; then
cdn="Cloudflare"
elif grep -q -i -E "^strict-transport-security: max-age=31536000" ${s}; then
if [[ $(grep -E -i -o  "incap_ses_|Incapsula|^X-Original-URl:|^x-i*nfo:" ${s} | wc -w) -gt 0 ]]; then
cdn="Imperva Incapsula"; fi
elif grep -q -i -E "OriginShieldHit|CloudFront-.*|X-Amz-Cf-Id" ${s}; then
cdn="Amazon AWS CloudFront" ; fi
if [ -n "$cdn" ] ; then
echo "$cdn" > $tempdir/cdn
echo -e "\nCDN:            $cdn\n"; else
echo 'null' > $tempdir/cdn; fi
}
f_LBD(){
local s="$*" ; echo '' ; f_Long ; echo "LOAD BALANCING DETECTION" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
echo -e "\nRunning lbd... [$s]\n"
timeout 240 ${PATH_lbd} ${s} > $tempdir/l_b
cat $tempdir/l_b | sed -n '/Checking for DNS-Loadbalancing:/,$p' | sed '/^$/d' | sed 's/\]:/\]:\n/' | sed 's/^ *//' | sed 's/, NOT FOUND/\nNOT FOUND/' |
sed '/Checking for/{x;p;x;}' | sed 's/\[Date\]:/\[Date\]:\n/' | sed 's/\[Diff\]:/\[Diff\]:\n/' | sed '/does/{x;p;x;G}' | fmt -s -w 60
}
f_inspectHEADERS(){
local s="$*"; f_Long; echo -e "HEADERS" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
link_headers=$(grep -E -i "^link" $s | cut -d '<' -f 2- | cut -d '>' -f 1 | sed 's/^ *//' | tr -d ' ')
links=$(grep -E -i "alternate|api\.w\.org" $s | cut -d '<' -f 2- | cut -d '>' -f 1 | sed 's/^ *//' | tr -d ' ')
c_control=$(grep -s -E -i "^cache-control:" ${s} | sed 's/[Cc]ache-[Cc]ontrol:/>/g' | tr '[:space:]' ' '; echo '')
expires=$(grep -E -a -i "^expires:" ${s} | tail -1 | sed 's/expires:/Expires:/')
s_instance=$(grep -s -E -i "^server-instance:" ${s} | sed 's/[Ss]erver-[Ii]nstance:/>/g')
xp_cache=$(grep -E -a -i "^x-proxy-cache:" ${s} | sed 's/[Xx]-[Pp]roxy-[Cc]ache:/>/g' | tr '[:space:]' ' '; echo '')
x_squid=$(grep -s -E -i "^x-squid:" ${s} | sed 's/[Xx]-[Ss]quid:/>/g' | tr '[:space:]' ' '; echo '')
x_varnish=$(grep -s -E -i "^x-varnish:" ${s} | sed 's/[Xx]-[Vv]varnish:/>/g' | tr '[:space:]' ' '; echo '')
vary=$(grep -s -E -i "^vary:" ${s} | sed 's/[Vv]ary:/ /g' | sed 's/^ *//' | tr '[:space:]' ' '; echo '')
via=$(grep -s -E -i "^via:" ${s} | sed 's/[Vv]ia:/ /g' | tr '[:space:]' ' '; echo '')
via_proxy=$(grep -s -E -i "^via-proxy:" ${s} | sed 's/[Vv]ia-[Pp]roxy:/>/g' | tr '[:space:]' ' '; echo '')
via_squid=$(grep -s -E -i "^via-squid:" ${s} | sed 's/[Vv]ia-[Ss]quid:/>/g' | tr '[:space:]' ' '; echo '')
via_squid=$(grep -s -E -i "^via-varnish:" ${s} | sed 's/[Vv]ia-[Vv]arnish:/>/g' | tr '[:space:]' ' '; echo '')
caching=$(grep -sEaio "^cache-control|^expires|^pragma|^strict-transport-security|^vary|^x-sfc-cachable|^x-sfc-tags|^x-proxy-cache" ${s} | sort -u |
tr '[:space:]' ' '; echo '')
cdn_headers=$(grep -sEaio "Server: AkamaiGHost|server: Akamai|server: AkamaiEdge|^x-akamai-transformed|Server: Cloudflare|cf-ray|cf-cache-status|incap_ses_|Incapsula|X-Original-URl|^x-i*nfo|OriginShieldHit|CloudFront-.*|X-Amz-Cf-Id|x-fastly-cache-status|fastly-restarts" ${s} | sort -u | tr '[:space:]' ' '; echo '')
[[ -n "$caching" ]] && echo -e "\nCACHING:\n"; [[ -n "$c_control" ]] && echo "Cache-Control: $c_control"
[[ -n "$vary" ]] && echo -e "Vary: $vary"; [[ -n "$expires" ]] && echo -e "$expires"
[[ -n "$cdn_headers" ]] && echo -e "\nCDN:\n\n$cdn_headers"
echo -e "\n\nSECURITY:\n"
if [ -n "$links" ] ; then
for l in $(echo "$links" | sort -u); do
curl -sILk -m 5 ${l} >> $tempdir/h3; echo -e "\n$l\n" >> $tempdir/sec_headers_alternate
f_getSecHEADERS "$tempdir/h3" >> $tempdir/sec_headers_alternate ; done
grep -E -i "^location:" ${s} | tail -1 | awk '{print $NF}'; echo  '' ; fi
f_getSecHEADERS "${s}" > $tempdir/sec_headers
if [[ $(cat $tempdir/sec_headers | wc -w) -lt 2 ]] ; then
echo -e "NA" ; else
cat $tempdir/sec_headers ; echo '' ; fi
if [ -n "$links" ] ; then
if [[ $(cat $tempdir/sec_headers_alternate | wc -l) -gt 3 ]] ; then
cat $tempdir/sec_headers_alternate; echo '' ; fi ; fi
echo -e "\nOTHER:\n"; [[ -n "$via" ]] && echo -e "Via: $via"; [[ -n "$via_proxy" ]] && echo -e "Via-Proxy: $via_proxy"
[[ -n "$via_squid" ]] && echo -e "Via-Squid: $via_squid"; [[ -n "$via_varnish" ]] && echo -e "Via-Varnish: $via_varnish"
[[ -n "$x_proxy" ]] && echo -e "X-Proxy: $x_proxy"; [[ -n "$x_squid" ]] && echo -e "X-Squid: $x_squid"
[[ -n "$x_varnish" ]] && echo -e "X-Varnish: $x_varnish"; [[ -n "$s_instance" ]] && echo -e "Server-Instance: $s_instance"
grep -sEai "*.forwarded:" ${s} | tail -1; grep -sEai "^x-forwarded-by:" ${s} | tail -1
grep -sEai "^x-client-location:" ${s} | tail -1; grep -sEai "^x-location:" ${s} | tail -1
grep -sEai "^x-pass:" ${s}  | tail -1; grep -sEai "^x-pass-why:" ${s} | tail -1; grep -sEai "^x-redirect-by:" ${s} | tail -1
grep -sEai "^X-Server-Name:" ${s} | tail -1; grep -s -E -i "^X-Served-By" ${s} | tail -1
grep -sEai "^X-Server-Generated:" ${s} | tail -1; grep -E -m 2 "HIT|MISS" ${s}; grep -sEai "^date:" ${s} | tail -1
grep -sEai "^Liferay-Portal" ${s}; grep -E -a -i "^upgrade:" ${s} | tail -1
grep -sEai "^X-AspNet-Version" ${s}; grep -sEai -m 1 "^X-TYPO3-.*" ${s}; grep -sEai -m 1 "^X-OWA-Version" ${s}
grep -sEai "^X-Generator:" ${s} | sort -u; grep -sEai "^X-Powered-By:" ${s} | sort -u; grep -sEai "^X-Version:" ${s} | tail -1
grep -i -E -v "^Server:|^Location:|^set-cookie:|^link:" ${s} |
grep -sEai "aix|asp\.net|azure|linux|centos|debian|red hat|rhel|solaris|suse|ubuntu" | sort -u
grep -i -E -v "^Server:|^Location:|^link:" ${s} | grep -sai 'azure' | sort -u; grep -sai "win32" ${s} | sort -u;
grep -E -a -i "win64" ${s} | sort -u; grep -sEai "^X-UA-Compatible:" ${s} | tail -1; grep -E -a -i "^x-robots-tag:" ${s} | tail -1
if [ -f $tempdir/sec_headers_alternate ]; then
rm $tempdir/sec_headers_alternate; fi
}
f_getSecHEADERS(){
local s="$*"; content_sec=$(grep -m 1 -i -o "^Content-Security-Policy:" ${s})
c_pol=$(grep -Eioa "block-all-mixed-content|connect-src|default-src|font-src|form-action|frame-ancestors|frame-src|img-src|manifest-src|media-src|object-src|plugin-types|reflected-xss|sandbox|script-nonce|script-src" ${s} | sort -u | tr '[:space:]' ' ' ; echo '')
grep -sEai "^access-control-allow-origin:" ${s} | tail -1 ; grep -s -a -E -i "^access-control-allow-headers:" ${s} | tail -1
grep -sEai "^access-control-allow-methods:" ${s} | tail -1; grep -sEai "^access-control-expose-headers:" ${s} | tail -1
grep -s -a -E -i "^allow:" ${s} | tail -1; grep -s -a -E -i "^clear-site-data " ${s} | tail -1
if [ -z "$c_pol" ]; then
grep -sEoai -m 1 "^Content-Security-Policy" ${s}; fi; grep -sEoai "^cross-origin-embedder-policy " ${s} | tail -1
grep -sEoai "^cross-origin-opener-policy" ${s} | tail -1; grep -sEoai "^cross-origin-resource-policy" ${s} | tail -1
grep -sEai "^expect-ct:" ${s} | tail -1; grep -sEai "^etag:" ${s} | tail -1; grep grep -sEai "^feature-policy" ${s} | tail -1
grep -sEoai -m 1  "^P3P" ${s}; grep -s -i -E -o -m 1 "^permissions-policy" ${s}
pragma=$(grep -sEai "^pragma:" ${s} | sed 's/[Pp]ragma:/>/g' | tr '[:space:]' ' '; echo '')
if [ -n "$pragma" ]; then
echo "Pragma: $pragma"; fi
grep -sEai "^referrer-policy:" ${s} | tail -1; grep -s -E -i "^Strict-Transport-Security:" ${s} | tail -1
grep -sEai "^X-Adblock-Key:" ${s} | tail -1; grep -sEoai -m 1 "^X-Content-Security-Policy" ${s}
grep -s -E -i "^X-Content-Type-Options:" ${s} | tail -1; grep -sEai "^X-Frame-Options:" ${s} | tail -1
grep -s -E -i "^X-Xss-Protection:" ${s} | tail -1; grep -sEoai "^X-WebKit-CSP" ${s} | tail -1
grep -E -i "^X-Permitted-Cross-Domain-Policies" ${s} | tail -1
if [ -n "$c_pol" ]; then
echo -e "\n$content_sec $c_pol"; fi
cookie_count=$(grep -s -i -o "^set-cookie:" ${s} | wc -w)
if [ $cookie_count != "0" ] ; then
path_flag=$(grep -s -i "^set-cookie:" ${s} | grep -s -i -o -a "path=*" | wc -w)
httponly=$(grep -s -i "^set-cookie:" ${s} | grep -s -i -o -a "httponly" | wc -w)
secure_flag=$(grep -s -i "^set-cookie:" ${s} | grep -s -i -o -a 'secure' | wc -w)
echo -e "\nCookies: $cookie_count  >  Flags:  HttpOnly: ${httponly}x | Path: ${path_flag}x | Secure: ${secure_flag}x"; fi
}

#********************** WEBSITE - WEB-TECHNOLOGIES & CONTENT **********************
f_TITLE(){
local s="$*"
if [ $option_connect = "0" ] ; then
title=$(grep -soP '(Title\[).*?(?=\])' $tempdir/ww.txt | tail -1 | sed 's/Title\[//' | tr -d '][' | sed 's/^ *//') ; else
title=$(grep -sEao "<title>.*.</title>" $s | sed -e :a -e 's/<[^>]*>//g;/</N;//ba' | sed 's/^[ \t]*//;s/[ \t]*$//')
if [ -z "$title" ] ; then
title=$(lynx -crawl -dump $s | grep -s TITLE | sed 's/THE_TITLE://' | sed 's/^[ \t]*//;s/[ \t]*$//') ; fi ; fi
echo -e "\nTitle:          $title"
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
if [[ $(grep -w -i -o  "Incapsula" $tempdir/cdn_detect | wc -w) = 0 ]]; then
timeout 3 ${PATH_lynx} -accept_all_cookies -dump -listonly -nonumbers ${s} > $tempdir/linkdump_raw
timeout 3 ${PATH_lynx} -accept_all_cookies -dump -listonly -nonumbers ${eff_url} >> $tempdir/linkdump_raw
cat $tempdir/linkdump_raw | sort -f -u | sed '/Sichtbare Links:/d' | sed '/Versteckte Links:/d' |
sed '/[Vv]isible [Ll]inks:/d' | sed '/[Hh]idden [Ll]inks:/d' > $tempdir/linkdump.txt ; fi
if [ $domain_enum = "true" ] && [ -n "$PATH_lynx" ]; then
curl -s https://api.hackertarget.com/pagelinks/?q=${s}${api_key_ht} >> $tempdir/linkdump.txt; fi
cat $tempdir/linkdump.txt | sort -u >> $tempdir/LINKS.${s}.txt ; fi
grep -E "^http:.*|^https:.*|^www.*|" $tempdir/linkdump.txt > $tempdir/linkdump
cat $tempdir/LINKS.${s}.txt >> ${outdir}/LINK_DUMP.${s}.txt
hosts_unique=$(grep -E "^http:.*|^https:.*|^www.*" $tempdir/linkdump | sed 's/http:\/\///' |
sed 's/https:\/\///' | cut -d '/' -f 1 | sort -u)
if [ -n "$hosts_unique" ] ; then
echo '' >> ${outdir}/LINK_DUMP.${s}.txt; f_Short  >> ${outdir}/LINK_DUMP.${s}.txt; echo -e "* Hosts\n" >> ${outdir}/LINK_DUMP.${s}.txt
for h in $hosts_unique ; do
ip_address=$(host -t a $h | grep 'has address' | awk '{print $NF}' | head -6 | tr '[:space:]' ' ')
echo -e "$h \n     $ip_address\n" ; done >> ${outdir}/LINK_DUMP.${s}.txt ; fi ; fi
}
f_ROBOTS(){
local s="$*"
if [[ $(grep -w -i -o  "Incapsula" $tempdir/cdn | wc -w) = 0 ]]; then
status_humans=$(curl -sLk $s/humans.txt -o $tempdir/humans -w %{http_code})
if [ $status_humans = "200" ] ; then
cat $tempdir/humans > $tempdir/humans.txt
if [[ $(grep -i -o "DOCTYPE" $tempdir/humans.txt | wc -w ) -gt 0 ]] ; then
rm $tempdir/humans.txt ; rm $tempdir/humans; else
rm $tempdir/humans; cat $tempdir/humans.txt >> $tempdir/cms
f_Long > ${outdir}/HUMANS.${s}.txt; echo "[+]  $s  |  humans.txt  |  $(date)" >> ${outdir}/HUMANS.${s}.txt
f_Long >> ${outdir}/HUMANS.${s}.txt; echo '' >> ${outdir}/HUMANS.${s}.txt
cat $tempdir/humans.txt >> ${outdir}/HUMANS.${s}.txt ; fi ; fi
status_robots=$(curl -sLk $s/robots.txt -o $tempdir/robots -w %{http_code})
if [ $status_robots = "200" ] ; then
cat $tempdir/robots > $tempdir/robots.txt
if [[ $(grep -i -o "DOCTYPE" $tempdir/robots.txt | wc -w ) -gt 0 ]] ; then
rm $tempdir/robots.txt ; rm $tempdir/robots; else
rm  $tempdir/robots; cat $tempdir/robots.txt >> $tempdir/cms
f_Long > ${outdir}/ROBOTS.${s}.txt
echo "[+]  $s  |  robots.txt  |  $(date)" >> ${outdir}/ROBOTS.${s}.txt; f_Long >> ${outdir}/ROBOTS.${s}.txt
echo '' >> ${outdir}/ROBOTS.${s}.txt; cat $tempdir/robots.txt >> ${outdir}/ROBOTS.${s}.txt ; fi ; fi ; fi
}
f_PAGE(){
local s="$*" ; echo ''
if [ $option_connect = "0" ]; then
targetURL=$(cut -s -d ']' -f 1 $tempdir/ww.txt | sed 's/\[/ /' | tail -1) ; else
status=$(grep -E "^Status:" $tempdir/response | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/HTTP /HTTP\//')
targetURL=$(grep -E "^URL:" $tempdir/response | cut -d ':' -f 2- | tr -d ' ')
f_detectCDN "$tempdir/headers" > $tempdir/cdn_detect; fi
targetHOSTNAME=$(echo $targetURL | sed 's/http:\/\///' | sed 's/https:\/\///' | cut -d '/' -f 1)
if [ -f $tempdir/ww ]; then
target_email=$(grep -s -oP '(Email\[).*?(?=])' $tempdir/ww.txt | sed 's/Email\[/\nEmail:          /' | tr -d ']' | sed 's/,/ /g')
httpserver=$(grep -s -oP '(HTTPServer\[).*?(?=\])' $tempdir/ww.txt | sed 's/HTTPServer\[//' | sed 's/^ *//' | tail -1)
cms=$(grep -s -E -i -o -m 1 "wordpress|typo3|joomla|drupal|liferay|librecms|wix" $tempdir/ww.txt | sort -u -V | tail -1)
google_a=$(grep -s -oP -m 1 '(Google-Analytics\[).*?(?=\,)' $tempdir/ww.txt | sed 's/ \[UA/: UA/'); fi
if echo $s | grep -q -E "\.edu\.|\.co\.|\.org.|\.gov\."; then
page_dom=$(echo $s | sed 's/http:\/\///' | sed 's/https:\/\///' | cut -d '/' -f 1 | rev | cut -d '.' -f 1,2,3 | rev) ; else
page_dom=$(echo $s | sed 's/http:\/\///' | sed 's/https:\/\///' | cut -d '/' -f 1 | rev | cut -d '.' -f 1,2 | rev) ; fi
if echo $targetURL | grep -q -E "\.edu\.|\.co\.|\.org.|\.gov\."; then
targetURL_dom=$(echo $eff_url | sed 's/http:\/\///' | sed 's/https:\/\///' | cut -d '/' -f 1 | rev | cut -d '.' -f 1,2,3 | rev) ; else
targetURL_dom=$(echo $eff_url | sed 's/http:\/\///' | sed 's/https:\/\///' | cut -d '/' -f 1 | rev | cut -d '.' -f 1,2 | rev) ; fi
if [ $option_connect = "0" ] ; then
if [ $domain_enum = "true" ] ; then
f_Long ; echo "[+] $s | DOMAIN WEBSITE" ; f_Long ; echo '' ; else
f_Long; echo "WHATWEB" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
sed -e '/./{H;$!d;}' -e 'x;/Meta-Refresh-Redirect/!d;' $tempdir/ww.txt | grep -s -oP '(Meta-Refresh-Redirect\[).*?(?=\])' | sed 's/\[/:\n/' |
sed 's/^ *//' | sed '/Meta-Refresh-Redirect:/{x;p;x;}'
sed -e '/./{H;$!d;}' -e 'x;/Meta-Refresh-Redirect/!d;' $tempdir/ww.txt | grep -s -oP '(Title\[).*?(?=\])' | sed 's/Title\[/\nTitle:\n/' | sed 's/^ *//'
echo ''; grep -s -oP '(RedirectLocation\[).*?(?=\])' $tempdir/ww.txt  | sed 's/RedirectLocation\[/\nRed. Location:  /g'; f_Short2; fi
target_email=$(grep -s -oP '(Email\[).*?(?=])' $tempdir/ww.txt | sed 's/Email\[/Email:          /' | tr -d ']' | sed 's/,/ /g')
httpserver=$(grep -s -oP '(HTTPServer\[).*?(?=\,)' $tempdir/ww.txt | sed 's/HTTPServer\[//' | sed 's/\]/ /g' | tr -d '[' | sed 's/^ *//' | tail -1)
cms=$(grep -s -E -i -o -m 1 "wordpress|typo3|joomla|drupal|liferay|librecms|wix" $tempdir/ww.txt | sort -u -V | tail -1)
google_a=$(grep -s -oP -m 1 '(Google-Analytics\[).*?(?=\,)' $tempdir/ww.txt | sed 's/ \[UA/: UA/')
if [ -n "$cms" ] ; then
cms_output="$cms" ; else
cms_output="none/unknown" ; fi ; f_TITLE; echo -e "\nServer:         $httpserver"; echo -e "\nCMS:            $cms_output\n"
if [ -n "$target_email" ] ; then
echo -e "$target_email\n" ; fi
if [ -n "$google_a" ] ; then
echo -e "Google:         Analytics: $google_a\n"; fi
echo ''; f_MARKUP ; echo ''
if [ $domain_enum = "true" ] && [ -n "$api_key_ht" ]; then
f_Long; echo -e "HTTP HEADERS\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
curl -s -m 5 "https://api.hackertarget.com/httpheaders/?q=${s}${api_key_ht}" > $tempdir/headers
echo '' >> $tempdir/headers; cat $tempdir/headers; fi
if [ -n "$api_key_ht" ] || [ $domain_enum = "true" ]; then
f_Long; echo -e "LINK DUMP\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
curl -s -m 5 https://api.hackertarget.com/pagelinks/?q=${s}${api_key_ht} > $tempdir/linkdump
echo '' >> $tempdir/linkdump; cat $tempdir/linkdump ; fi; else
endpoint=$(grep 'Connected to' $tempdir/curl_trimmed | tail -1 | awk '{print $3,$4}')
if [ $domain_enum = "true" ] ; then
f_Long ; echo "[+]  DOMAIN WEBSITE" ; f_Long
echo -e "\nHost            $endpoint" ; else
verify=$(grep -s -m 1 'SSL certificate verify' $tempdir/curl_trimmed | grep -Eo "ok|unable to get" | sed 's/unable to get/error/')
f_Long ; echo "$s | SSL: $verify | STATUS: $status" ; f_Long
echo -e "\nURL:            $targetURL" ; fi
if [[ $(cat $tempdir/cdn_detect | wc -w) -gt 1 ]]; then
cat $tempdir/cdn_detect; fi
if [[ $(grep -w -i -o  "Incapsula" $tempdir/cdn | wc -w) -gt 0 ]]; then
echo -e "\n\nImperva Incapsula CDN detected.\n\nAborting attemps to scrape website..." ; else
f_ROBOTS "${s}"; f_linkDUMP "${s}"
doctype=$(grep -E -i "<\!doctype" $tempdir/page_src | grep -i -o -E "XHTML.[1-2]|HTML.[1-4]|<\!doctype html>" | tr [:lower:] [:upper:] |
sed 's/<!DOCTYPE HTML>/HTML5/')
x_powered=$(grep -E -i -a "^X-Powered-By:" $tempdir/headers | tr [:upper:] [:lower:] | cut -d ':' -f 2- | sed 's/^ *//' | sort -u |
tr '[:space:]' ' '; echo'')
grep -E "src=|href=" $tempdir/page_src | grep -soP '(type=").*?(?=")' | grep -E -o "text/\b[A-Za-z0-9.+]{1,30}\b|application/\b[A-Za-z0-9.+]{1,30}\b" |
sed 's/^ *//' | sed '/^$/d' >> $tempdir/mime_types
grep -soP '(type=").*?(?=")' $tempdir/src_scripts | grep -E -o "text/\b[A-Za-z0-9.+]{1,30}\b|application/\b[A-Za-z0-9.+]{1,30}\b" |
sed 's/^ *//' | sed '/^$/d' >> $tempdir/mime_types
if ! [ -f $tempdir/ww ]; then
google_a=$(grep -a -m 1 -E -o "UA-[0-9-]{6,18}" $tempdir/page_src | head -1)
httpserver=$(grep -i -E "^Server:" $tempdir/headers  | cut -d ':' -f 2 | sed 's/^[ \t]*//;s/[ \t]*$//' | tail -1)
cms=$(grep -s -E -i -o "wordpress|wp-content|wp-includes|wp-admin|typo3|typo3search|typo3conf|typo3.conf|joomla|drupal|liferay|librecms|wix" $tempdir/cms |
sed 's/typo3conf/typo3/g' | sed 's/typo3.conf/typo3/g' | sed 's/typo3search/typo3/g' | sed 's/TYPO3SEARCH/TYPO3/g' |
sed 's/wp-content/wordpress/g' | sed 's/wp-admin/wordpress/g' | sed 's/wp-includes/wordpress/g' | sed 's/^[ \t]*//;s/[ \t]*$//' |
tr [:lower:] [:upper:] | sort -uV | tail -1); rm $tempdir/cms; fi
if [ -n "$cms" ] ; then
cms_output="$cms" ; else
cms_output="none/unknown" ; fi ; f_TITLE "$tempdir/page.html"; echo -e "\nServer:         $httpserver"
if [ $page_details = "false" ] ; then
echo -e "\n\nCMS:            $cms_output\n"; echo -e "Doctype:        $doctype\n"
if [ -n "$google_a" ] ; then
echo -e "Google:         Analytics ID: $google_a\n" ; fi; else
echo -e "\nCMS:            $cms_output\n"
if [ -f $tempdir/ww.txt ] ; then
f_Long; fi
echo -e "\nDoctype:        $doctype"
grep -E -o "lang=.?.?" $tempdir/no_quotes | head -1 | sed 's/lang=/Language:       /'
grep -A1 '<link' $tempdir/page_src | grep -o -m 1 'xmlrpc.php' >> $tempdir/webtech_n_style
grep -C 1 'stylesheet' $tempdir/page_src | grep -E -o -m 1 "font-awesome|fontawesome" | head -1 | sed 's/-//' |
sed 's/fontawesome/FontAwesome/' >> $tempdir/webtech_n_style
grep -E -o "class=fas|class=fab|class=fa" $tempdir/page_src | sed 's/class=//g' | sed 's/fa/FontAwesome/g' | sed 's/fab/FontAwesome/g' |
sed 's/fas/FontAwesome/g' >> $tempdir/webtech_n_style
grep -E "src=|href=" $tempdir/page_src | grep 'fonts.googleapis' | grep -soP '(family=).*?(?=\,)' | cut -d ':' -f 1 |
sed 's/family=/GoogleWebFonts:/' >> $tempdir/webtech_n_style
if [ -f $tempdir/ww.txt ]; then
f_MARKUP; else
grep -soP '(name=generator content=).*?(?=>)' $tempdir/no_quotes | sed 's/name=generator/MetaGenerator:  /' | sed 's/content=//' |
awk -F'\"' '{print $1}'
if [ -n "$x_powered" ] ; then
echo -e "X-Powered-by:   $x_powered"; fi
grep -soP '(name=author content=).*?(?=>)' $tempdir/no_quotes | sed 's/name=author/Author:        /' | sed 's/content=//' |
awk -F'>' '{print $1}' | tr -d '/'
rss_feed=$(grep -i 'application/rss+xml' $tempdir/page_src | grep -E -o "href=*.*>" | head -1 | cut -d '=' -f 2 | tr -d '\"' | tr -d ' ')
metarob=$(grep -sP '(name=robots content=).*?(?=>)' $tempdir/no_quotes | awk -F'content=' '{print $2}' | awk -F'>' '{print $1}' | tr '[:space:]' ' ' |
sed 's/^ *//'; echo '')
cookies=$(grep -E -i "^set-cookie:" $tempdir/headers | cut -d ' ' -f 2- | cut -d '=' -f 1 | sort -u | tr '[:space:]' ' ' | sed 's/ /  /g' |
sed 's/^ *//'; echo '')
if [ -n "$metarob" ] ; then
echo "MetaRobots:     $metarob" ; fi
if [ -n "$rss_feed" ] ; then
echo "RSSFeed:        $rss_feed" | sed 's/href=//' | tr -d '>'; fi
if [ -n "$cookies" ] ; then
echo "Cookies:        $cookies"; fi; fi
timeout 5 ${PATH_lynx} -accept_all_cookies -crawl -dump -nonumbers $s > $tempdir/pages_text
mime_types=$(grep '/' $tempdir/mime_types | sort -u)
if [ -n "$mime_types" ]; then
echo ''; f_Long; echo -e "MIME TYPES (APPLICATION/TEXT)\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; echo "$mime_types"; fi
script_src=$(grep -A 2 '<script' $tempdir/page_src | grep -soiP '(src=").*?(?=")' | awk -F'src=' '{print $2}' | tr -d '\"')
if [ -n "$script_src" ] ; then
echo ''; f_Long ; echo -e "SCRIPTS\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
echo "$script_src" | sort -u | sed 's/;/;\n/g' | fmt -w 100; echo '' ; fi
theme_info=$(sed -n '/<head>/,/<\/head>/p' $tempdir/page_src | grep -E "Theme:|Version:|WP:")
if [ -n "$theme_info" ] ; then
f_Long ; echo -e "WP THEME INFO\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
echo -e "$theme_info\n" | fmt -w 120; fi
page_descr=$(grep -siP '(name=description content=).*?(?=>)' $tempdir/no_quotes | awk -F'content=' '{print $2}' | awk -F'>' '{print $1}' | tr -d '/')
page_keyw=$(grep -siP '(name=keywords content=).*?(?=>)' $tempdir/no_quotes | awk -F'content=' '{print $2}' | awk -F'>' '{print $1}' | tr -d '/' |
sed 's/,/ /g')
if [ -n "$page_descr" ] ; then
f_Long; echo -e "DESCRIPTION\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; echo -e "$page_descr\n" | fmt -w 60 -s ; fi
if [ -n "$page_keyw" ] ; then
if [ -n "$page_descr" ] ; then
echo ''; fi
echo -e "KEYWORDS\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; echo "$page_keyw" | fmt -w 60 -s ; fi
grep 'property=og:type' $tempdir/no_quotes | grep -soP '(content=).*?(?=/>)' | sed 's/content=/Type:   /' > $tempdir/ograph
grep 'property=og:locale' $tempdir/no_quotes | grep -soP '(content=).*?(?=/>)' | sed 's/content=/Locale: /' >> $tempdir/ograph
grep 'property=og:site_name' $tempdir/no_quotes | grep -soP '(content=).*?(?=/>)' | sed 's/content=/Site:   /' >> $tempdir/ograph
grep 'property=og:url' $tempdir/no_quotes | grep -soP '(content=).*?(?=/>)' | sed 's/content=/URL:    /' >> $tempdir/ograph
grep 'property=og:title' $tempdir/no_quotes | grep -soP '(content=).*?(?=/>)' | sed 's/content=/Title:  /' >> $tempdir/ograph
grep 'property=og:description' $tempdir/no_quotes | grep -soP '(content=).*?(?=/>)' | sed 's/content=/\nDescription:\n\n/' |
sed 's/^ *//' >> $tempdir/ograph
if [[ $(cat $tempdir/ograph | wc -w) -gt 1 ]] ; then
f_Long; echo -e "OPEN GRAPH PROTOCOL\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
cat $tempdir/ograph | fmt -s -w 60; fi
echo ''; cat $tempdir/page.html > $tempdir/pages
for site in $subpages1 ; do
curl -sLk ${curl_ua} ${s}/$site >> $tempdir/pages ; done
if [ $domain_enum = "true" ]; then
for site2 in $subpages2 ; do
curl -sLk ${curl_ua} ${site2}.${targetURL_dom} >> $tempdir/pages; done; fi
grep -s -i -F -econtact -ediscord -ekontakt -efacebook -einstagram -elinkedin -epinterest -etwitter -exing -eyoutube $tempdir/linkdump.txt |
sed '/sport/d' | sed '/program/d' > $tempdir/social
grep -sEo "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/ww.txt > $tempdir/contacts_mail
grep -E -i "Phone|Ph:|Telefon:|Tele:|Tel:|Telefone:|Fon:|Mobile:|Contact:|contact-us:|kontakt|service|support|customer.*" $tempdir/pages |
grep -E -o "\+[0-9]{2,6}[ -][0-9]{2,6}[ -][0-9]{2,6}[ -][0-9]{2,6}|\(([0-9]\{3\})\|[0-9]\{3\}\)[ -]\?[0-9]\{3\}[ -]\?[0-9]\{4\}" >> $tempdir/phone
grep -s -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/linkdump.txt | tr [:upper:] [:lower:] >> $tempdir/contacts_mail
grep -s -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/pages | tr [:upper:] [:lower:] >> $tempdir/contacts_mail
cat $tempdir/pages_text | sed 's/-at-/@/g' |  sed 's/(at)/@/g' | sed 's/@ /@/g' | sed 's/ @/@/g' | tr [:upper:] [:lower:] >> $tempdir/pages.txt
grep -E -i "Phone|Ph:|Telefon:|Tele:|Tel:|Telefone:|Fon:|Mobile:|Contact:|contact-us:|kontakt|service|support|customer.*" $tempdir/pages.txt |
grep -E -o "\+[0-9]{2,6}[ -]*[0-9]{2,6}[ -][0-9]{2,6}[ -][0-9]{2,6}|\(([0-9]\{3\})\|[0-9]\{3\}\)[ -]\?[0-9]\{3\}[ -]\?[0-9]\{4\}" >> $tempdir/phone
grep -s -E -i "^tel:|^phone:|^call:|^telefon:|^fon|contact|contact-us|kontakt" $tempdir/linkdump.txt | cut -d ':' -f 2- | tr -d ' ' |
grep -E -o "\+[0-9]{2,6}[ -]*[0-9]{2,6}[ -][0-9]{2,6}[ -][0-9]{2,6}|\(([0-9]\{3\})\|[0-9]\{3\}\)[ -]\?[0-9]\{3\}[ -]\?[0-9]\{4\}" >> $tempdir/phone
grep -s -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/pages.txt | tr [:upper:] [:lower:] >> $tempdir/contacts_mail
website_mail=$(cat $tempdir/contacts_mail | sort -u | grep -E -v "\.jpg|\.png|\.gif|\.tiff|\.ico")
f_Long; echo -e "SOCIAL MEDIA & CONTACTS" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' ; echo '' ; cat $tempdir/social | sort -f -u ; echo ''
if [ -f $tempdir/phone ]; then
cat $tempdir/phone | sort -uV; fi
if [ -n "$website_mail" ]; then
if [ -f $tempdir/phone ]; then
echo '' ; fi
echo "$website_mail"; fi; echo ''
beacons=$(grep -E -A 3 "<noscript>" $tempdir/no_quotes | grep -E "height=[0-2]|width=[0-2]")
if [ $domain_enum = "true" ] ; then
if [ -n "$google_a" ] ; then
echo ''; f_Long; search_item=$(echo $google_a | cut -d '-' -f -2); echo -e "Google Analytics ID Reverse Search [$search_item]\n"
rev_ga=$(curl -s https://api.hackertarget.com/analyticslookup/?q=${search_item})
if [ -n "$rev_ga" ] ; then
for ga in $rev_ga ; do
echo -e "\n$ga   -  $(dig +short $ga)" ; done ; fi ; fi ; fi
if [ -n "$beacons" ] ; then
if [[ $(echo "$beacons" | wc -w) -lt 50 ]] ; then
f_Long ; echo -e "WEB BEACONS\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' ; echo -e "$beacons\n" | sort -u | fmt -s -w 80; fi ; fi
if [ -f $tempdir/humans.txt ] ; then
if [[ $(cat $tempdir/humans.txt | wc -l) -lt 15 ]] ; then
f_Long ; echo -e "HUMANS.TXT\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
cat $tempdir/humans.txt; echo '' ; fi ; fi
if [ -f $tempdir/robots.txt ] ; then
if [[ $(cat $tempdir/robots.txt | wc -l) -lt 41 ]] ; then
f_Long ; echo -e "ROBOTS.TXT\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
cat $tempdir/robots.txt; echo '' ; fi; fi; fi; fi
if [ $domain_enum = "false" ]; then
echo ''; f_Long; echo "DNS" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
echo -e "DNS FORWARD CHAIN\n"
f_dnsFOR_CHAIN "${s}"
if [[ $(jq -r '.data.forward_nodes' $tempdir/chain.json | tr -d '}[,"{' | sed 's/^ *//' | sed '/^$/d' | sed 's/\]//g' | wc -l) -lt 12 ]]; then
echo -e "\nFORWARD CONFIRMED RDNS"
nmap -Pn -sn -R --resolve-all --script fcrdns 2> /dev/null $s | grep -E "scan report|\||\|_" | sed 's/fcrdns: //g' | sed 's/^|_//g' |
sed 's/^|//g' | sed '/^$/d' | sed 's/Nmap scan report for/\n*/g' | sed 's/(/ (/g' | sed 's/FAIL/  FAIL/g' |
sed '/FAIL/{x;p;x;}'
if [ -n "$target6" ] ; then
nmap -6 -Pn -sn -R --resolve-all --script fcrdns 2> /dev/null $s | grep -E "scan report|\||\|_" | sed 's/fcrdns: //g' | sed 's/^|_//g' |
sed 's/^|//g' | sed '/^$/d' | sed 's/Nmap scan report for/\n*/g' | sed 's/(/ (/g' | sed 's/FAIL/  FAIL/g' |
sed '/FAIL/{x;p;x;}'; fi; echo ''; fi
if ! [ "$s" = "$targetHOSTNAME" ]; then
echo -e "\n\nDNS FORWARD CHAIN\n"
f_dnsFOR_CHAIN "${targetHOSTNAME}"
if [[ $(jq -r '.data.forward_nodes' $tempdir/chain.json | tr -d '}[,"{' | sed 's/^ *//' | sed '/^$/d' | sed 's/\]//g' | wc -l) -lt 12 ]]; then
echo -e "\nFORWARD CONFIRMED RDNS"
nmap -Pn -sn -R --resolve-all --script fcrdns 2> /dev/null $targetHOSTNAME | grep -E "scan report|\||\|_" | sed 's/fcrdns: //g' | sed 's/^|_//g' |
sed 's/^|//g' | sed '/^$/d' | sed 's/Nmap scan report for/\n*/g' | sed 's/(/ (/g' | sed 's/FAIL/  FAIL/g' |
sed '/FAIL/{x;p;x;}'
if [ -n "$target6" ] ; then
nmap -6 -Pn -sn -R --resolve-all --script fcrdns 2> /dev/null $targetHOSTNAME | grep -E "scan report|\||\|_" | sed 's/fcrdns: //g' | sed 's/^|_//g' |
sed 's/^|//g' | sed '/^$/d' | sed 's/Nmap scan report for/\n*/g' | sed 's/(/ (/g' | sed 's/FAIL/  FAIL/g' |
sed '/FAIL/{x;p;x;}'; fi; echo '' ; fi; fi
if [[ $(grep -w -i -o  "Incapsula" $tempdir/cdn | wc -w) = 0 ]] && [ $request_times = "1" ]; then
f_requestTIME "${s}"; fi
echo ''; f_Long; echo -e "WHOIS STATUS\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; f_whoisSTATUS "${s}"
if ! [ "$page_dom" = "$targetURL_dom" ]; then
echo ''; f_whoisSTATUS "${targetURL_dom}"; fi; echo ''
echo "$target4" > $tempdir/server_ipv4; echo "$target6" > $tempdir/server_ipv6
host $targetHOSTNAME | grep -w 'has address' | awk '{print $NF}' | tr -d ' ' >> $tempdir/server_ipv4
host $targetHOSTNAME | grep -w 'has IPv6 address' | awk '{print $NF}' | tr -d ' ' >> $tempdir/server_ipv6
if [ $page_details = "false" ] && [ $bl_check = "true" ]; then
for a in $(cat $tempdir/server_ipv4 | sort -uV); do
f_webSHORT "${a}"; done
if [ -f $tempdir/server_ipv6 ]; then
for z in $(cat $tempdir/server_ipv6 | sort -uV); do
f_webSHORT "${z}"; done; fi
if [ -f $tempdir/prefixes.list ]; then
echo ''; for pfx in $(cat $tempdir/prefixes.list | sort -uV); do
f_PREFIX "${pfx}"; done; fi; fi
if [ $page_details = "false" ] && [ $bl_check = "false" ]; then
echo ''; for a in $(cat $tempdir/server_ipv4 | sort -uV); do
f_hostSHORT "${a}"; done
if [ -f $tempdir/server_ipv6 ]; then
for z in $(cat $tempdir/server_ipv6 | sort -uV); do
f_hostSHORT "${z}"; done; fi; fi; fi; fi
}
f_MARKUP(){
if [ -f $tempdir/ww.txt ]; then
script=$(grep -s -oP '(Script\[).*?(?=\])' $tempdir/ww.txt | cut -d '[' -f 2- | sed 's/,/\n/g' | sort -u | tr '[:space:]' ' ' |
sed 's/ /  /' | sed 's/^ *//')
if [ -z "$script" ] ; then
script=$(grep -o -m 1 'Script' $tempdir/ww.txt); fi
jqu=$(grep -s -oP '(JQuery\[).*?(?=\,)' $tempdir/ww.txt | sort -u | tr '[:space:]' ' ')
if [ -z "$jqu" ] ; then
jqu=$(grep -o -m 1 'JQuery' $tempdir/ww.txt); fi
cookies=$(grep -s -oP '(Cookies\[).*?(?=\])' $tempdir/ww.txt | cut -d '[' -f 2- | sed 's/,/\n/g' | sort -u | tr '[:space:]' ' '; echo '')
uncommon_headers=$(grep -s -oP '(UncommonHeaders\[).*?(?=\])' $tempdir/ww.txt | cut -d '[' -f 2- | sed 's/,/\n/g' | sed 's/^ *//')
if [ $option_connect = "0" ] ; then
doctype=$(grep -s -o -w 'HTML5' $tempdir/ww.txt | tail -1)
if [ -n "$doctype" ] ; then
doctype="$doctype" ; else
doctype="HTML4.x/XHTML1.x or similar" ; fi
echo -e "\nDoctype:        $doctype"
grep -s -oP -m 1 '(Content-Language\[).*?(?=\])' $tempdir/ww.txt | sed 's/Content-Language\[/Language:       /' | tr -d ']'; fi
if [ -n "$script" ] || [ -n "$jqu" ] ; then
echo -e "Script:         $script $jqu\n"; fi
if ! [ $option_connect = "0" ] && [ -n "$google_a" ] ; then
echo "Google:         Analytics ID: $google_a" ; fi
grep -s -oP '(PoweredBy\[).*?(?=\])' $tempdir/ww.txt | sed 's/\[/:      /' | sort -u
grep -s -oP '(X-Powered-By\[).*?(?=\])' $tempdir/ww.txt | sed 's/\[/:   /' | sort -u
grep -s -oP '(MetaGenerator\[).*?(?=\])' $tempdir/ww.txt | sed 's/\[/:  /' | sort -u
grep -oP '(Meta-Author\[).*?(?=,)' $tempdir/ww.txt | sed 's/Meta-Author\[/Author:         /' | tr -d '][' | sed 's/^ *//'
if ! [ $option_connect = "0" ] ; then
rss_feed=$(grep -i 'application/rss+xml' $tempdir/page_src | grep -E -o "href=*.*>" | head -1 | cut -d '=' -f 2 | tr -d '\"' | tr -d ' ')
metarob=$(grep -sP '(name=robots content=).*?(?=>)' $tempdir/no_quotes | awk -F'content=' '{print $2}' | awk -F'>' '{print $1}' |
tr '[:space:]' ' ' | sed 's/^ *//'; echo '')
if [ -n "$metarob" ] ; then
echo "MetaRobots:     $metarob" ; fi
if [ -n "$rss_feed" ] ; then
echo "RSSFeed:        $rss_feed" | sed 's/href=//' | tr -d '>'; fi; fi
grep -s -oP '(PasswordField\[).*?(?=\])' $tempdir/ww.txt | sed 's/PasswordField\[/PasswdField:    /' | tr -d ']'
grep -s -oP '(WWW-Authenticate\[).*?(?=\])' $tempdir/ww.txt | sort -u | sed 's/WWW-Authenticate\[/WWW-Auth.:     /' | tr -d ']['
grep -s -o -w 'Frame' $tempdir/ww.txt | head -1 >> $tempdir/webtech_n_style
grep -o -m 1 'OpenSearch' $tempdir/ww.txt >> $tempdir/webtech_n_style
grep -o -m 1 'Modernizr' $tempdir/ww.txt >> $tempdir/webtech_n_style
grep -o -m 1 'Lightbox' $tempdir/ww.txt >> $tempdir/webtech_n_style
grep -s -oP -m 1 '(Open-Graph-Protocol\[).*?(?=\])' $tempdir/ww.txt | sed 's/\[/:/' >> $tempdir/webtech_n_style
if [ $option_connect = "0" ] ; then
grep -s -oP '(X-UA-Compatible\[).*?(?=\])' $tempdir/ww | sed 's/\[/: /' >> $tempdir/webtech_n_style; fi
webtech_other=$(cat $tempdir/webtech_n_style | sort -ufV | tr '[:space:]' ' '; echo '')
if [ -n "$webtech_other" ] ; then
echo -e "Other:          $webtech_other"; fi
if [ -n "$cookies" ] ; then
echo -e "Cookies:        $cookies"; fi
grep -s -oP '(Via-Proxy\[).*?(?=\])' $tempdir/ww.txt | sed 's/\[/:      /'
if ! [ $option_connect = "0" ] && [ -n "$uncommon_headers" ]; then
uncommon_headers_connect=$(echo "$uncommon_headers" | grep -i -v "x-content-type-options")
if [ -n "$uncommon_headers_connect" ]; then
echo -e "\n\nUncommon Headers:\n"; echo -e "$uncommon_headers_connect" | sort -u; fi; fi
if [ $option_connect = "0" ] ; then
grep -s -oP '(Strict-Transport-Security\[).*?(?=\])' $tempdir/ww.txt | tail -1 | sed 's/\[/: /' | tr -d '][' > $tempdir/sec_headers_ww
grep -s -oP '(X-Frame-Options\[).*?(?=\])' $tempdir/ww.txt | tail -1 | sed 's/\[/:  /' | tr -d ']['  >> $tempdir/sec_headers_ww
grep -s -oP '(X-XSS-Protection\[).*?(?=\])' $tempdir/ww.txt | tail -1 | sed 's/\[/:  /' | tr -d ']['  >> $tempdir/sec_headers_ww
grep -i -o 'content-security-policy' $tempdir/ww.txt | tail -1  >> $tempdir/sec_headers_ww
grep -i -o 'x-content-type-options' $tempdir/ww.txt | tail -1  >> $tempdir/sec_headers_ww
grep -s -oP '(Cookies\[).*?(?=\])' $tempdir/ww.txt | sed 's/\[/:  /' | tr -d ']['  >> $tempdir/sec_headers_ww
grep -s -oP '(HttpOnly\[).*?(?=\])' $tempdir/ww.txt | sed 's/\[/:  /' | tr -d ']['  >> $tempdir/sec_headers_ww
if [ -f $tempdir/sec_headers_ww ] || [ -n "$uncommon_headers" ] ; then
echo ''; f_Long ; echo -e "UNCOMMON & SECURITY HEADERS\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
echo "$uncommon_headers"; cat $tempdir/sec_headers_ww; rm $tempdir/sec_headers_ww; fi ; fi ; fi
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
if ! [ $option_sslscan = "0" ] ; then
if [ -z "$PATH_sslscan" ] ; then
echo ''; f_Long; echo -e "\nPlease install SSLscan or set path to executable within the drwho.sh file" ; else
local s="$*"
if [ $option_sslscan = "1" ] ; then
echo ''; f_Long; echo "SSL CIPHERS & SECURITY - SUMMARY" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
${PATH_sslscan} --no-colour --no-cipher-details --no-groups --no-fallback --show-times $s | sed 's/^[ \t]*//;s/[ \t]*$//' > $tempdir/sslscn
sed -n '/SSL\/TLS Protocols:/,/SSL Certificate/p' $tempdir/sslscn |
grep -E -v "^SSL Certificate:" | sed '/Protocols:/{x;p;x;G}' | sed '/Supported Server/{x;p;x;G;}' | sed '/TLS renegotiation:/{x;p;x;}'; fi
if [ $option_sslscan = "2" ] ; then
echo -e "\n___________________________________________________________________\n"; echo -e "SERVER CIPHERS - TIMES\n\n"
o="--no-colour --tlsall --no-fallback --no-compression --no-groups --no-heartbleed --no-renegotiation --no-cipher-details --no-check-certificate --show-times"
${PATH_sslscan} ${o} ${s} | sed 's/^[ \t]*//;s/[ \t]*$//' > $tempdir/sslscn
sed -n '/Supported Server/,/SSL Certificate:/p' $tempdir/sslscn | sed '/Supported Server/d' | sed '/SSL Certificate:/d' | sed '/^$/d' ; fi
if [ $option_sslscan = "3" ] ; then
echo ''; f_Long
if [ $option_starttls = "2" ] ; then
${PATH_sslscan} --no-colour --starttls-imap --no-cipher-details --no-groups --no-fallback --show-times --ocsp $s:$mx_port |
sed 's/^[ \t]*//;s/[ \t]*$//' > $tempdir/sslscn ; else
${PATH_sslscan} --no-colour --starttls-smtp --no-cipher-details --no-groups --no-fallback --show-times --ocsp $s:$mx_port |
sed 's/^[ \t]*//;s/[ \t]*$//' > $tempdir/sslscn ; fi
sed -n '/Connected to/,/Stapling Request/p' $tempdir/sslscn | sed '/Protocols:/{x;p;x;G}' | sed '/Stapling Request/d' |
sed '/TLS renegotiation:/{x;p;x;G}' | sed '/TLS Compression:/{x;p;x;G}' | sed '/Heartbleed:/{x;p;x;G}' | sed 's/using SNI name/\n\nSNI name:/'
sed -n '/OCSP Stapling Request:/,/Supported Server/p' $tempdir/sslscn | grep -E "OCSP|Cert Status:|Hash:|Update:|Serial Number:|Responder Id:" |
sed '/Cert Status:/{x;p;x;G}' | sed '/Request:/{x;p;x;G}'; echo ''
sed -n '/Supported Server/,/SSL Certificate:/p' $tempdir/sslscn | sed '/Supported Server/{x;p;x;G}' | sed '/SSL Certificate:/d'
sed -n '/Subject:/,/Issuer:/p' $tempdir/sslscn | sed '/Issuer:/d' | sed 's/Subject:/\n\nSubject:\n\n/' |
sed 's/Altnames:/\n\nAltnames:\n\n/' | sed 's/DNS://g' | sed 's/^ *//' | fmt -s -w 80 ; fi ; fi; fi
}
f_testSSL_OUT(){
local s="$*"; cat ${s} |
sed '/Start/i \\n___________________________________________________________________\n' | sed 's/^.*\(-->>.*\).*$/\1/g' |
sed '/Common Name (CN)/i \\n___________________________________________________________________\n' | sed 's/Common Name (CN)             /CN: /g' |
sed '/NULL ciphers /i \\n___________________________________________________________________\n\n' | sed 's/-->>//g' | sed 's/<<--//g' |
sed 's/SSLv2/\n\nSSLv2/g' | sed '/SSL Session ID support /i \___________________________________________________________________\n\n' |
sed '/SSLv3/G' | sed '/NPN\/SPDY/{x;p;x;}' | sed '/Export/{x;p;x;}' | sed '/Triple/{x;p;x;}' | sed '/Strong encryption/{x;p;x;}' |
sed '/HTTP Status Code /i \\n___________________________________________________________________\n\n' |
sed '/visibility info/{x;p;x;}' | sed 's/(CN in response/\n(CN in response/g' | sed '/Chain of/G' | sed '/Transparency/{x;p;x;}' |
sed '/Intermediate Bad OCSP/{x;p;x;}' | sed '/Trust (hostname)/i \___________________________________________________________________\n\n' |
sed '/DNS CAA/G' | sed '/Intermediate cert/i \\n___________________________________________________________________\n' |
sed '/Forward Secrecy strong/G' | sed '/Heartbleed/i \\n___________________________________________________________________\n\n' |
sed '/Hexcode/i \\n\n--------------------------------------------------------------------------' |
sed '/Hexcode/a \--------------------------------------------------------------------------\n' | sed '/Server key size/{x;p;x;}' |
sed '/Browser/i \\n\n------------------------------------------------------------------------------------------------' |
sed '/Browser/a \------------------------------------------------------------------------------------------------\n' |
sed 's/Intermediate cert validity/Intermediate cert validity\n\n/g' | tr -d '#' | sed 's/^[ \t]*//;s/[ \t]*$//'
}
f_testSSL(){
if ! [ $option_testSSL = "0" ] ; then
if [ -z "$PATH_testssl" ] ; then
echo ''; f_Long; echo -e "\nPlease install SSLscan or set path to executable within the drwho.sh file" ; else
local s="$*"; declare -a testssl_array=()
if [ -n "$target6" ]; then
testssl_array+=(-6); fi
if [ $option_testSSL = "1" ] ; then
testssl_array+=(--sneaky --phone-out --quiet --warnings off --color 0 -S -s -p)
elif [ $option_testSSL = "2" ] ; then
if [ -n "$PATH_sslscan" ]; then
testssl_array+=(--sneaky --phone-out --quiet --warnings off --color 0 -S -s -p -H -R -B -C -Z); else
testssl_array+=(--ids-friendly --phone-out --mapping no-iana --quiet --warnings off --color 0 -S -p -s -e -H -R -C -Z); fi
elif [ $option_testSSL = "3" ] ; then
testssl_array+=(--ids-friendly --warnings off --mapping no-iana --phone-out --quiet --color 0 -S -p -s -e -h -B -C -H -R -T -WS -Z)
if [ $client_sim = "true" ]; then
testssl_array+=(-c); fi; fi
if [ $option_testSSL = "3" ] ; then
timeout 600 ${PATH_testssl} ${testssl_array[@]} $s | sed 's/^[ \t]*//;s/[ \t]*$//' |
grep -v -E "^rDNS:|^Service detected:|^TLS extensions|^Serial|extended master|^Signature Algorithm|Revocation List|OCSP stapling|Certificate Validity|No connection|^Done" | sed '/^$/d' > $tempdir/testtls; else
timeout 600 ${PATH_testssl} ${testssl_array[@]} $s | sed 's/^[ \t]*//;s/[ \t]*$//' |
grep -v -E "^rDNS:|^Service detected:|^TLS extensions|^Serial|extended master|key size|key usage|^Signature Algorithm|Revocation List|OCSP stapling|Certificate Validity|No connection|^Done" | sed '/^$/d' > $tempdir/testtls; fi
if [ $option_testSSL = "1" ] ; then
grep -E "^Start|^SSLv2|^SSLv3|^TLS.[.0-3]{1,3}|NULL|Export|LOW:|Triple DES|Obsoleted CBC|Strong encryption|Forward Secrecy strong|Common Name|^Trust|^Chain of|pwnedkeys\.com|visibility info|DNS CAA|OCSP URI|Transparency|provided|^Intermediate|<--" $tempdir/testtls > $tempdir/opt1
f_testSSL_OUT "$tempdir/opt1"
elif [ $option_testSSL = "2" ] ; then
if [ -n "$PATH_sslscan" ]; then
grep -E "^Start|^SSLv2|^SSLv3|^TLS.[.0-3]{1,3}|^NPN/SPDY|^ALPN/HTTP2|NULL|export|LOW:|Triple DES|^Obsoleted|^Strong encryption|^Forward Secrecy|^SSL Session ID|Session Resumption|^TLS clock|^Certificate Compression|Authentication|Common Name|^Trust|^Chain of|pwnedkeys\.com|^OCSP URI|must staple|Transparency|^Certificates provided|<--|vulnerable|Secure Renegotiation|fallback|BREACH" $tempdir/testtls > $tempdir/opt2; else
grep -E "^Start|SSLv2|SSLv3|TLS.[.0-3]{1,3}|^NPN/SPDY|^ALPN/HTTP2|NULL|export|LOW:|Triple DES|^Obsoleted CBC|^Strong encryption|^Forward Secrecy|ID support|Session Resumption|TLS clock|^Certificate Compression|Authentication|Common Name|^Trust|^Chain of|visibility info|pwnedkeys\.com|OCSP URI|must staple|DNS CAA|Transparency|^Certificates provided|^Intermediate|<--|vulnerable|fallback|Secure Renegotiation|BREACH|Hexcode|^x.[0-9a-f]{2,4}" $tempdir/testtls > $tempdir/opt2; fi
f_testSSL_OUT "$tempdir/opt2"
elif [ $option_testSSL = "3" ] ; then
cat $tempdir/testtls |
grep -E "^Start|^SSLv2|^SSLv3|TLS.[.0-3]{1,3}|^NPN/SPDY|^ALPN/HTTP2|NULL|export|LOW:|Triple DES|^Obsoleted CBC|^Strong encryption|^Forward Secrecy|^SSL Session ID|Session Resumption|TLS clock|Compression|Authentication|key size|key usage|Common Name|^Trust|^Chain of|visibility info|pwnedkeys\.com|OCSP URI|must staple|DNS CAA|Transparency|^Certificates provided|^Intermediate|<--|Intermediate Bad|^HTTP Status Code|^HTTP clock|^Strict Transport|^Server banner|^Public Key Pinning|vulnerable|fallback|Renegotiation|BREACH|Hexcode|^x.[0-9a-f]{2,4}|Browser|^Android|^Chrome|^Firefox|^Edge|^IE 11|^Safari|^Java|^OpenSSL" > $tempdir/opt3
f_testSSL_OUT "$tempdir/opt3"; fi; fi; fi
}
f_certINFO() {
local s="$*"; exp=''
if [ $option_connect = "0" ] ; then
curl -s "https://api.certspotter.com/v1/issuances?domain=${s}&expand=dns_names&expand=issuer&expand=cert" > $tempdir/hostcert.json
dnsnames=$(jq -r '.[].dns_names | .[]' $tempdir/hostcert.json)
if [ -n "$dnsnames" ] ; then
f_Long ; echo "SSL CERTIFICATES" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
jq -r '.[] | {Subject: .dns_names[], Issuer: .issuer.name, Expires: .not_after, CertSHA256: .cert.sha256}' $tempdir/hostcert.json | tr -d '}"{,' |
sed 's/^ *//' | sed '/^$/d' | sed 's/C=/\nC: /g' | sed 's/ST=/\nST=/g' | sed 's/L=/\nL=/g' | sed 's/OU=/\nOU=/g' | sed 's/O=/\nO:/g' | sed 's/CN=/\nCN:/g' |
sed 's/^ *//' | sed '/^ST=/d' | sed '/^OU=/d' | sed '/^L=/d' | tr '[:space:]' ' ' | sed 's/Subject:/\n\nSUBJECT:/g' | sed 's/Expires:/\nEXPIRES:/g' |
sed 's/Issuer:/\n\nISSUER:/g' | sed 's/CertSHA256:/\nSHA256: /g' | sed 's/ O:/| O: /g' | sed 's/ CN:/| CN: /g' | sed 's/^ *//' | sed '/SHA256:/G'; fi; else
if [ $type_mx = "true" ]; then
f_Long; echo -e "$s\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
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
mx_port="993" ; fi ; fi; else
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
pubkey=$(grep -w -A 1 "Public Key Algorithm:" $tempdir/x509.txt | cut -d ':' -f 2- | sed 's/^ *//' | tr '[:space:]' ' '; echo '')
sign_algo=$(grep -w -i -m 1 "Signature Algorithm:" $tempdir/x509.txt | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
no_response=$(grep -s -w -i -o "no response sent"  $tempdir/ssl_status.txt | sed 's/^[ \t]*//' | sed 's/no response/no OCSP response/')
cert_status=$(grep -s -i -w 'Cert Status:' $tempdir/ssl_status.txt | sed 's/Cert Status: good/ok/' | sed 's/^ *//')
if [ -n "$cert_status" ] ; then
ocsp_status="$cert_status" ; else
ocsp_status="$no_response" ; fi
if [ -n "$exp" ]; then
if [ $target_type = "web_short" ]; then
f_Long; echo -e "$s\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; fi
if [ $target_type = "dnsrec" ] || [ $target_type = "web_short" ]; then
export mx_port; echo -e "\nStatus:        $verify  ($start_date - $ex_date)" ; else
if [ $quiet_dump = "false" ] ; then
echo -e "\n"; f_Long ; echo "[+] SSL |  $s  |  STATUS:  $verify  " ; f_Long
echo -e "\nValid:         $start_date - $ex_date" ; else
echo -e "\n$s: Certificate found - $verify" ; fi ; fi
echo -e "\nStatus:        $verify,  $start_date - $ex_date" > $tempdir/ssl1
if [ -n "$s_org" ] ; then
echo -e "\nSubject:       $s_cn  ($s_org from $s_cc)" > $tempdir/ssl2; else
echo -e "\nSubject:       $s_cn  $s_cc" > $tempdir/ssl2; fi
echo -e "\nOCSP:          $ocsp_status" >> $tempdir/ssl2
echo -e "\nIssuer:        $ca_cn  ($ca_org from $ca_cc)" >> $tempdir/ssl2 ; cat $tempdir/ssl2
if [ $target_type = "dnsrec" ]; then
echo -e "\n\nSHA-1:         $sha_1" ; echo -e "\nSerial:        $serial"
echo -e "\n\nCipher:        $protocol | $cipher | $t_key\n"; echo -e "PubKey:        $pubkey\n"; else
if [ $quiet_dump = "false" ] ; then
echo -e "\n___________________________________________________________________\n"; echo -e "Fingerprints (SHA1)\n"
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
echo -e "___________________________________________________________________\n" > $tempdir/ssl3
echo -e "\nSerial:        $serial\n" >> $tempdir/ssl3; echo -e "Signature:     $sign_algo" >> $tempdir/ssl3
echo -e "PubKey:        $pubkey" >> $tempdir/ssl3; echo -e "\nCipher:        $protocol | $cipher | $t_key" >> $tempdir/ssl3; cat $tempdir/ssl3
if [ $cert_dump = "true" ]; then
echo '' > ${outdir}/CERT.${s}.txt; f_Long >> ${outdir}/CERT.${s}.txt; echo "[+] $s | CERTIFICATE FILE DUMP | $(date)" >> ${outdir}/CERT.${s}.txt
f_Long >> $outdir/CERT.${s}.txt; cat $tempdir/ssl1 >> $outdir/CERT.${s}.txt; cat $tempdir/ssl2 >> ${outdir}/CERT.${s}.txt
echo '' >> ${outdir}/CERT.${s}.txt; cat $tempdir/ssl3 >> ${outdir}/CERT.${s}.txt; fi
if [ $quiet_dump = "false" ] && ! [ $target_type = "web_short" ]; then
echo -e "\n___________________________________________________________________\n"
if [ $target_type = "other" ]; then
echo -e "OCSP:\n"; grep -s -w -i -o "no response sent"  $tempdir/ssl_status.txt | sed 's/^[ \t]*//'
grep -s -i -w 'OCSP Response Status:' $tempdir/ssl_status.txt | sed 's/^[ \t]*//'
grep -s -i -w 'Responder Id:' $tempdir/ssl_status.txt | sed 's/^[ \t]*//'
grep -s -i -w 'Cert Status:' $tempdir/ssl_status.txt | sed 's/^ *//'
grep -s "OCSP - URI" $tempdir/x509.txt | cut -d ':' -f 2- | sed 's/^ *//'
grep -s 'Subject OCSP hash:' $tempdir/x509.txt | sed 's/^ *//'
grep -s 'Public key OCSP hash:' $tempdir/x509.txt | sed 's/^ *//'
echo -e "\n___________________________________________________________________\n"; fi
echo -e "Subject AltNames\n"
sed -e '/./{H;$!d;}' -e 'x;/Subject Alternative Name:/!d;' $tempdir/x509.txt | grep 'DNS:' | sed 's/DNS://g' | sed 's/^ *//' | fmt -s -w 70; fi
if [ $cert_dump = "true" ]; then
echo -e "\n___________________________________________________________________\n" >> $outdir/CERT.${s}.txt
cat $tempdir/x509.txt | grep -E "serial=|SHA1 Fingerprint=" | sed 's/serial=/\nSerial:\n/' |
sed 's/SHA1 Fingerprint=/SHA1 Fingerprint:\n/' >> $outdir/CERT.${s}.txt
echo -e "\n___________________________________________________________________\n" >> $outdir/CERT.${s}.txt
sed -n '/Certificate chain/,/Server certificate/p' $tempdir/chain.txt | sed 's/s:/Holder: /g' | sed 's/i:/Issuer: /g' | sed '/END/G' |
sed '/BEGIN/{x;p;x}' | sed '$d' >> ${outdir}/CERT.${s}.txt
echo '' >> ${outdir}/CERT.${s}.txt; sed -n '/X509v3 extensions:/,/SHA1/p' $tempdir/x509.txt |
sed '$d' | sed '/Subject Key Identifier:/{x;p;x;}' | sed '/Policies:/{x;p;x;}' | sed '/Subject OCSP/{x;p;x;}' |
sed '/SCTs/{x;p;x;}' | sed '/SHA1/d' | sed '/Signature Algorithm:/{x;p;x;G}' | sed '/Timestamp:/{x;p;x;}' |
sed '/Constraints:/{x;p;x;}' | sed '/extensions:/{x;p;x;}' | sed '/Policies:/{x;p;x;}' |
sed '/Alternative Name:/{x;p;x;G}' >> ${outdir}/CERT.${s}.txt; fi; fi
if [ $quiet_dump = "false" ] ; then
f_SSLSCAN "${s}"; f_testSSL "${s}"; echo ''; fi; else
echo -e "\nNo certificate found for $s.\n"; fi ; fi
}

#********************** DOMAIN STATUS SUMMARY, WHOIS STATUS, DNS FORWARD CHAIN ***********************
f_whoisSTATUS(){
local s="$*"
if echo $s | grep -q -E "\.edu\.|\.co\.|\.org.|\.gov\."; then
whois_query=$(echo $s | sed 's/http:\/\///' | sed 's/https:\/\///' | cut -d '/' -f 1 | rev | cut -d '.' -f 1,2,3 | rev) ; else
whois_query=$(echo $s | sed 's/http:\/\///' | sed 's/https:\/\///' | cut -d '/' -f 1 | rev | cut -d '.' -f 1,2 | rev) ; fi
if echo $s | grep -q -E "\.de"; then
whois -h whois.denic.de -- "-T dn $whois_query" | sed '/^%/d' | sed 's/^ *//' | sed '/^$/d' > $tempdir/whois_domain; else
whois $whois_query | sed '/please/d' | sed '/%/d' | sed '/REDACTED/d' | sed '/for more/d' | sed 's/^ *//' | sed '/^$/d' > $tempdir/whois_domain; fi
grep -E -i "^No match for" $tempdir/whois_domain | head -1
if echo $s | grep -q -E "\.jp"; then
sed -n '/Domain Information:/,$p' $tempdir/whois_domain ; else
if [[ $(grep -o -c 'VeriSign' $tempdir/whois_domain) -gt 0 ]]; then
grep -E "^Domain Name:" $tempdir/whois_domain | head -1 | sed 's/Domain Name:/Domain Name:     /g'
if [[ $(sed -n '/Domain Name:/,/Domain Name:/p' $tempdir/whois_domain | grep -o -E -c "^Domain Status:") -gt 1 ]]; then
sed -n '/Domain Name:/,/Domain Name:/p' $tempdir/whois_domain | grep -E "^Registrar URL:|^Registrar WHOIS Server:|Date:|Contact Email:|Phone:" > $tempdir/temp; else
sed -n '/Domain Name:/,/Domain Name:/p' $tempdir/whois_domain | grep -E "^Registrar URL:|^Registrar WHOIS Server:|Date:|^Domain Status:|Contact Email:|Phone:|^DNSSEC:" |
awk -F'https://icann.org' '{print $1}' > $tempdir/temp; fi
cat $tempdir/temp | sed 's/Registrar Abuse Contact Email:/Abuse Email:     /g' | sed 's/Registrar Abuse Contact Phone:/Abuse Phone:     /g' |
sed 's/Domain Status:/\nDomain Status:/' | sed 's/Registry Expiry Date:/Registry Expires:/g' | sed 's/Domain Status:/Domain Status:   /g' |
sed 's/URL:/URL:   /g' | sed 's/Updated Date:/Updated Date:    /g' | sed 's/Creation Date:/Creation Date:   /g' | sed 's/DNSSEC:/DNSSEC:          /g' |
sed 's/Registrar WHOIS Server:/WHOIS Server:    /g' | awk -F 'T0' '{print $1}'
if [[ $(sed -n '/Domain Name:/,/Domain Name:/p' $tempdir/whois_domain | grep -o -E -c "^Domain Status:") -gt 1 ]]; then
grep -E "^DNSSEC:" $tempdir/whois_domain | sort -u | sed 's/DNSSEC:/DNSSEC:          /g'
echo -e "\n\nDOMAIN STATUS:\n"
grep -E "^Domain Status:" $tempdir/whois_domain | cut -d ':' -f 2- | sed 's/^ *//' | awk -F'https://icann.org' '{print $1}' |
tr '[:space:]' ' ' | fmt -s -w 60; echo ''; fi; else
grep -E -a -i "^domain:|^domain name:" $tempdir/whois_domain | head -1
grep -i -E -m 1 -A 1 "^domain:|^domain name:" $tempdir/whois_domain | tail -1 | grep -v ':'
grep -E -i -m 1 "registrar:" $tempdir/whois_domain | head -1
grep -E -i -m 1 "registrant:" $tempdir/whois_domain | head -1
grep -E -a -i "^status:|^domain status:|^registered" $tempdir/whois_domain | awk -F'https:' '{print $1}' | sort -u
grep -E -i -m 1 "^Registry Expiry Date:|expiry date|expires:" $tempdir/whois_domain | sort -u
grep -E -a -i -m 1 "^updated:|^changed:|update" $tempdir/whois_domain >> $tempdir/whois_domain_temp
grep -E -a -i "Re-registration" $tempdir/whois_domain | head -1 >> $tempdir/whois_domain_temp
cat $tempdir/whois_domain_temp | sort -u
grep -E -a -i -m 1 "country:" $tempdir/whois_domain
grep -E -a -i -m 1 "city:" $tempdir/whois_domain
grep -E -a -i -m 1 "phone:" $tempdir/whois_domain
grep -E -a -i -m 2 "^Company English Name|Company Chinese Name:" $tempdir/whois_domain
grep -E -a -m 1 "^admin-c:" $tempdir/whois_domain
whois_mail=$(grep -E -i -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/whois_domain | sort -uf | head -2 | tr '[:space:]' ' '; echo '')
if [ -n "$whois_email" ]; then
echo -e "Contact:  $whois_email"; fi
grep -E -i -m 1 "^dnssec:" $tempdir/whois_domain | tail -1; fi; echo ''
if [[ $(grep -o -E -c "^No match for" $tempdir/whois_domain) = 0 ]]; then
grep -sEai "^Nserver:|^Name Server:|^nameserver:" $tempdir/whois_domain | cut -d ':' -f 2- | sed 's/^ *//' | cut -d ' ' -f 1 > $tempdir/whois_ns_list
grep -E -A 10 "^nameservers:|^NAMESERVERS" $tempdir/whois_domain |
grep -E -i -o "\b[A-Za-z0-9]+[-_\.]+[A-Za-z0-9]+\.[A-Za-z]{2,6}\b" | sed 's/^ *//' >> $tempdir/whois_ns_list
if [ -f $tempdir/whois_ns_list ]; then
echo -e "\nNAME SERVERS:\n"; cat $tempdir/whois_ns_list | tr '[:space:]' ' ' | fmt -s -w 60; echo ''
rm $tempdir/whois_ns_list; echo ''; fi; fi; fi
}
f_dnsFOR_CHAIN(){
local s="$*"; auth_ns=''; query=$(echo $s | sed 's/http[s]:\/\///' | cut -d '/' -f 1 | tr -d ' ')
curl -s -m 5 --location --request GET "https://stat.ripe.net/data/dns-chain/data.json?resource=$query" > $tempdir/chain.json
auth_ns=$(jq -r '.data.authoritative_nameservers[]?' $tempdir/chain.json | sed '/null/d')
if [ -n "$auth_ns" ]; then
export auth_ns; if [[ ${query} =~ ":" ]] || [[ ${query} =~ $REGEX_IP4 ]] ; then
jq -r '.data.reverse_nodes' $tempdir/chain.json | tr -d '}[,"{' | sed 's/^ *//' | sed '/^$/d' | sed 's/\]//g' > $tempdir/chain.txt; else
jq -r '.data.forward_nodes' $tempdir/chain.json | tr -d '}[,"{' | sed 's/^ *//' | sed '/^$/d' | sed 's/\]//g' > $tempdir/chain.txt;fi
cat $tempdir/chain.txt; jq -r '.data.authoritative_nameservers[]?' $tempdir/chain.json | sort -V | tr '[:space:]' ' ' | fmt -s -w 80; echo ''; fi
}
f_DNSWhois_STATUS(){
local s="$*" ; f_Long; echo -e "WHOIS STATUS, DNS FORWARD CHAIN\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
f_whoisSTATUS "${s}"; echo ''; f_dnsFOR_CHAIN "${s}"
if [ $target_type = "default" ] && [[ ${s} =~ $REGEX_DOMAIN ]]; then
if [ $option_enum1 = "2" ] ; then
echo ''; f_Long; echo -e "THREAT CROWD API" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' ; f_THREATCROWD "${s}"; fi; fi
}
f_domainSTATUS(){
local s="$*" ; echo ''
f_Long; echo "[+] $s  | DOMAIN STATUS SUMMARY"; f_Long; echo -e "WEBSITE STATUS" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
if [ $option_connect = "0" ] ; then
eff_url=$(cut -s -d ']' -f 1 $tempdir/ww.txt | sed 's/\[/ /' | tail -1)
echo '' ; cut -s -d ']' -f 1 $tempdir/ww.txt | sed 's/\[/ /' | sed G; else
eff_url=$(grep "^URL:" $tempdir/response | cut -d ':' -f 2- | sed 's/^ *//')
status=$(grep 'Status:' $tempdir/response | cut -d ':' -f 2- | sed 's/^ *//')
verify=$(grep -s -m 1 'SSL certificate verify' $tempdir/curl_trimmed | tr -d '.' | grep -E -o "ok|unable to get local issuer certificate")
echo -e "\nWebsite:       $eff_url" ; echo -e "Status:        $status"; echo -e "SSL:           $verify\n" ; fi
target_hostname=$(echo $eff_url | sed 's/http:\/\///' | sed 's/https:\/\///' | cut -d '/' -f 1)
if echo $eff_url | grep -q -E "\.edu\.|\.co\.|\.org.|\.gov\."; then
target_url_dom=$(echo $eff_url | sed 's/http:\/\///' | sed 's/https:\/\///' | cut -d '/' -f 1 | rev | cut -d '.' -f 1,2,3 | rev) ; else
target_url_dom=$(echo $eff_url | sed 's/http:\/\///' | sed 's/https:\/\///' | cut -d '/' -f 1 | rev | cut -d '.' -f 1,2 | rev) ; fi
f_DNSWhois_STATUS "${s}" > $tempdir/domain_status
if ! [ "$s" = "$target_url_dom" ] ; then
f_DNSWhois_STATUS "${target_hostname}" | tee -a $tempdir/domain_status > $tempdir/domain_status_2
if [[ $(grep -E -w "^$target_url_dom" $tempdir/domain_status_2 | wc -l) = 0 ]]; then
f_dnsFOR_CHAIN "${target_url_dom}"; fi ; else
if [[ $(grep -E -w "^$target_host" $tempdir/chain.txt | wc -l) = 0 ]]; then
f_dnsFOR_CHAIN "^$target_host" >> $tempdir/domain_status ; fi; fi
echo '' >> $tempdir/domain_status; f_Long >> $tempdir/domain_status
echo -e "THREAT CROWD API" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' >> $tempdir/domain_status
f_THREATCROWD "${s}" >> $tempdir/domain_status
if ! [ "$s" = "$target_url_dom" ] ; then
f_THREATCROWD "${target_url_dom}" >> $tempdir/domain_status; fi ; cat $tempdir/domain_status
}
f_THREATCROWD(){
local s="$*"; curl -s "https://threatcrowd.org/searchApi/v2/domain/report/?domain=$s" > $tempdir/tcrowd_$s.json
resolutions=$(jq -r '.resolutions[] | {Date: .last_resolved, IP: .ip_address}?' $tempdir/tcrowd_$s.json | tr -d '{,\"}' | sed 's/^ *//' | sed '/^$/d' |
sed 's/IP:/-/g' | grep -w -v 'null' | tr '[:space:]' ' ' | sed 's/Date: /\n\n/g' ; echo '')
emails=$(jq -r '.emails[]?' $tempdir/tcrowd_$s.json | grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b")
if [ -n "$resolutions" ] ; then
echo -e "\nDNS RESOLUTIONS  ($s)"; echo -e "$resolutions\n"
if [ -n "$emails" ] ; then
echo -e "\nE-MAIL ADDRESSES\n"; echo -e "$emails\n"; fi; else
echo -e "No results for $s"; fi
}
#********************** IP REPUTATION & BOGON CHECK ***********************
f_BLOCKLISTS(){
local s="$*" ; reverse=$(echo $s | awk -F'.' '{printf $4 "." $3 "." $2 "." $1}')
for i in ${blocklists} ; do
in_list="$(dig @1.1.1.1 +short -t a ${reverse}.${i}.)"
if [[ $in_list ]]; then
if [ $target_type = "hop" ]; then
echo -e "! DNS Blocklists:      $i"; else
echo -e "  !                    $i   ($in_list)"; fi; else
echo -e "NO | $i"; fi; done
}
f_blocklistCHECK() {
local s="$*"
for i in $(cat $s | sort -u -V) ; do
if [ $target_type = "net" ] ; then
bl_entries=$(f_BLOCKLISTS "${i}" | grep -v "NO")
if echo $bl_entries | grep -q -E "!"; then
echo -e "\n !!! $i !!! \n" ; echo -e "\n\n$i\n" >> $tempdir/listings
echo "$bl_entries" | grep -v "NO" | tee -a $tempdir/listings
echo -e "\n" | tee -a $tempdir/listings ; else
echo -e "+ $i  OK\n" ; fi ; else
bl_entries=$(f_BLOCKLISTS "${i}" | grep -v "NO")
if echo $bl_entries | grep -q -E "!"; then
if [ $target_type = "hop" ]; then
echo -e "+ DNS Blocklists:      $i:"; else
echo -e "+ DNS Blocklists:      $i LISTED in:" ; fi
echo "$bl_entries" | grep -v "NO"; else
echo -e "+ DNS Blocklists:      Not listed [$i]" ; fi ; fi ; done
}
f_BOGON() {
local s="$*"; net_ip=$(echo $s | cut -d '/' -f 1 | tr -d ' ')
if [[ ${net_ip} =~ $REGEX_IP4 ]] ; then
reverse=$(echo $net_ip | awk -F'.' '{printf $4 "." $3 "." $2 "." $1}')
query="$(dig @1.1.1.1 +short ${reverse}.v4.fullbogons.cymru.com TXT | tr -d '\"' | sed 's/^ *//' | tr -d ' ')"
elif [[ ${net_ip} =~ ":" ]] ; then
nibble=$(host $net_ip | sed 's/Host //' | cut -d ' ' -f 1 | sed 's/.ip6.arpa//' | tr -d ' ')
query="$(dig @1.1.1.1 +short ${nibble}.v6.fullbogons.cymru.com TXT | tr -d '\"' | sed 's/^ *//' | tr -d ' ')"; fi
if [[ $query ]]; then
bogon="TRUE"; bogon_prefix=$(echo $query | tr -d '"' | tr -d ' '); else
bogon="FALSE"; fi; export bogon; export bogon_prefix
}
f_TOR1() {
local s="$*" ; reverse=$(echo $s | awk -F'.' '{printf $4 "." $3 "." $2 "." $1}')
is_tor=$(dig @1.1.1.1 +short -t a $(echo $s | awk -F'.' '{printf $4 "." $3 "." $2 "." $1}').tor.dan.me.uk.)
if [[ $is_tor ]]; then
echo "TOR: true (${is_tor})" ; else
echo "TOR: false" ; fi
}
f_TOR2() {
local s="$*" ; reverse=$(echo $s | awk -F'.' '{printf $4 "." $3 "." $2 "." $1}')
is_tor=$(dig @1.1.1.1 +short -t a $(echo $s | awk -F'.' '{printf $4 "." $3 "." $2 "." $1}').tor.dan.me.uk.)
if [[ $is_tor ]]; then
echo "+ TOR Node:            true   [$s]"; else
echo "+ TOR Node:            false  [$s]" ; fi
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
local s="$*"; backs=$(dig @1.1.1.1 +short -t a $(echo $s | awk -F'.' '{printf $4 "." $3 "." $2 "." $1}').ips.backscatterer.org.)
if [[ $backs ]]; then
echo "+ backscatterer.org:   $s is LISTED on ips. backscatter.org" ; else
echo "+ backscatterer.org:   Not listed [$s]" ; fi
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
if [[ $(cat $tempdir/attacks | wc -l) -gt 3 ]] ; then
echo -e "\n\nRecent Incidents (Times, Ports)\n"
tail -49 $tempdir/attacks ; rm $tempdir/attacks ; fi; else
echo "+ I.net Storm Center:  No results for $s"; fi
}
f_projectHONEYPOT(){
local s="$*" ; rev=$(echo $s | awk -F'.' '{printf $4 "." $3 "." $2 "." $1}')
if [ -n "$honeykey" ] ; then
response=$(dig +short ${honeykey}.${rev}.dnsbl.httpbl.org)
if [[ -z "$response" ]]; then
echo "+ Project Honeypot:    No results for $s" ; else
last_seen=$(echo "$response" | awk -F'.' '{print $2}') ; score=$(echo "$response" | awk -F'.' '{print $3}')
category=$(echo "$response" | awk -F'.' '{print $4}')
if [ $category = "0" ] ; then
agent_cat="Search Engine"
elif [ $category = "1" ] ; then
agent_cat="Suspicious"
elif [ $category = "2" ] ; then
agent_cat="Harvester"
elif [ $category = "4" ] ; then
agent_cat="Comment Spammer"
elif [ $category = "5" ] ; then
agent_cat="Suspicious & Comment Spammer"
elif [ $category = "6" ] ; then
agent_cat="Harvester & Comment Spammer" ; fi
if [ $category = "0" ] ; then
if [ $score = "0" ]; then
third_octett="Undocumented Searchengine"
elif [ $score = "3" ] ; then
third_octett="Baidu"
elif [ $score = "5" ] ; then
third_octett="Google"
elif [ $score = "8" ] ; then
third_octett="Yahoo" ; else
third_octett="Searchengine (Misc.)" ; fi ; fi
if ! [ $category = "0" ] ; then
third_octett="$score" ; fi
if [ $category = "0" ] ; then
echo -e "+ PROJECT HONEYPOT:\n  Category: $agent_cat | Agent: $third_octett | Last Seen: $last_seen  day(s) ago\n"; else
echo -e "+ PROJECT HONEYPOT:\n  Category: $agent_cat | Threat Score: $third_octett | Last Seen: $last_seen  day(s) ago\n"; fi ; fi ; else
echo -e "+ Project Honeypot:    API key required; for more information, select option h) 'help'"; fi
}
f_greyNOISE(){
local s="$*"; curl -m5 -s "https://api.greynoise.io/v3/community/$s" > $tempdir/gn.json
last_seen=$(jq -r '.last_seen' $tempdir/gn.json | sed '/null/d')
message=$(jq -r '.message' $tempdir/gn.json)
if [ -n "$last_seen" ] ; then
echo -e "\n+ GREYNOISE COMMUNITY API"
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
echo -e "\n+ STOP FORUM SPAM"
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
if ! [ $target_type = "hop" ]; then
f_projectHONEYPOT "${s}"; f_forumSPAM "${s}"; fi; f_SPAMHAUS "${s}"
if [ $domain_enum = "false" ]; then
if [ $target_type = "web" ] || [ $target_type = "other" ]; then
f_TOR2 "${s}" ; fi; fi; echo $s > $tempdir/bl_check
f_blocklistCHECK "$tempdir/bl_check"; f_greyNOISE "${s}"
if [ $target_type = "other" ]; then
f_threatSUMMARY "${s}" ; fi
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
f_Long; echo -e "AS $asn" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; echo -e "ABUSE CONTACT\n"
f_AS_ABUSEMAIL "${asn}"; echo -e "\n[@]:  $asabuse_c" ; else
f_Long; echo -e "$s" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
curl -m 5 -s "https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=${s}" > $tempdir/ac.json
rir=$(jq -r '.data.authoritative_rir' $tempdir/ac.json) ; abuse_mbox=$(jq -r '.data.abuse_contacts[]' $tempdir/ac.json | tr '[:space:]' ' ' ; echo '')
f_Long; echo -e "$s" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; echo -e "ABUSE CONTACT\n"
if [ -n "$abuse_mbox" ] ; then
echo -e "\n[@]:  $abuse_mbox (source: RipeStat)\n" ; else
if [ $rir = "arin" ] || [ $rir = "lacnic" ] ; then
whois -h whois.${rir}.net $s > $tempdir/whois ; else
whois -h whois.${rir}.net -- "--no-personal $s" | sed 's/^ *//' > $tempdir/whois; fi
abuse_mbox=$(grep -E -a -s -m 1 "^OrgAbuseEmail:|^% Abuse|^abuse-mailbox:|^e-mail:|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/whois |
grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b")
if [ -z "$abuse_mbox" ] ; then
abuse_mbox=$(grep -E -o -m 2 "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/whois); fi
echo -e "\n[@]:  $abuse_mbox (source: whois.$rir.net)\n" ; fi ; fi
}

#********************** DNS RECORDS & SUBDOMAINS ***********************
f_DNS_REC(){
local s="$*" ; srv_rec='' ; nss='' ; mxs=''
if [ -f $tempdir/rec_ips.list ] ; then
rm $tempdir/rec_ips.list ; fi ; echo ''; f_Long
if [ $dns_summary = "true" ] ; then
echo "[+]  DNS RECORDS SUMMARY  |  $s"; else
echo "[+]  DNS RECORDS  |  $s"; fi
if [ $domain_enum = "true" ]; then
f_Long; else
f_DNSWhois_STATUS "${s}"; echo ''; f_Long; fi
if [ $option_ttl = "2" ] ; then
ttl="+ttlunits" ; else
ttl="+ttlid" ; fi
echo -e "\nDOMAIN HOST\t\t\t${s}\n"
dig ${dig_array[@]} ${ttl} $s | grep -w 'A' | tee $tempdir/hostsA.list | awk '{print $2,$3,$4}' | sed 's/ /\t\t/g'
dig aaaa ${dig_array[@]} ${ttl} $s | grep -w 'AAAA' | tee $tempdir/hostsAAAA.list | awk '{print $2,$3,$4}' | sed 's/ /\t\t/g'
egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/hostsA.list | tee $tempdir/rec_ips.list >> $tempdir/ips.list
if [ -f $tempdir/hostsAAAA.list ] ; then
awk '{print $NF}' $tempdir/hostsAAAA.list > $tempdir/rec_ips6.list; fi
echo '' ; f_MX "${s}" ; echo ''
f_Long; f_NS "${s}"; txt_rec=$(dig ${nssrv} +short txt ${s})
if [ $dns_summary = "true" ] ; then
if [ -n "$txt_rec" ] ; then
echo ''; f_Long; echo -e "\nTXT RECORDS\n"; echo "$txt_rec" | sed '/\"/{x;p;x;}' | fmt -s -w 80 ; fi
f_NSEC "${s}"; f_Long; echo -e "\nPTR RECORDS\n\n"
for a in $(cat $tempdir/rec_ips.list | sort -uV); do
ptr=$(host $a ${nsserv} | grep -E "name pointer" | rev | cut -d ' ' -f 1 | rev | tr '[:space:]' ' ')
if [ -n "$ptr" ] ; then
echo -e "$a \n"; echo -e "$ptr\n" | fmt -s -w 60 | sed 's/^/     /g' ; else
echo -e "$a \n\n     no PTR record\n" ; fi ; done
dnsrec_v6=$(cat $tempdir/rec_ips6.list | sort -uV)
if [ -n "$dnsrec_v6" ] ; then
for z in $dnsrec_v6 ; do
ptr=$(host $z ${nsserv} | grep -E "name pointer" | rev | cut -d ' ' -f 1 | rev | tr '[:space:]' ' ')
if [ -n "$ptr" ] ; then
echo -e "$z \n"; echo -e "$ptr\n" | fmt -s -w 60 | sed 's/^/     /g' ; else
echo -e "$z \n\n     no PTR record\n" ; fi ; done ; fi
cat $tempdir/rec_ips.list > $tempdir/dnsrec_ips; if [ -f $tempdir/rec_ips6.list ] ; then
cat $tempdir/rec_ips6.list >> $tempdir/dnsrec_ips; fi
echo ''; f_pwhoisBULK "$tempdir/dnsrec_ips"; else
echo "$txt_rec" | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}' >> $tempdir/txt_nets
txt_ips=$(echo "$txt_rec" | egrep -o -v '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}' |
egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
if [ -n "$txt_ips" ] ; then
echo "$txt_ips" | tee $tempdir/txt_ip.list >> $tempdir/rec_ips.list ; fi
if [ $option_connect = "0" ] ; then
echo '' ; f_Long; else
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
if [ $rfc1912 = "true" ]; then
f_RFC1912 "${s}" ; else
echo '' ; f_Long ; fi
if [ -f $tempdir/mx4.list ] ; then
echo -e "BACKSCATTERER.IO\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
echo -e "Checking MX records for known backscatterers ...\n\n"
for i in $(egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/mx4.list | sort -uV) ; do
f_bSCATTERER "${i}" ; done; fi
if [ $dns_summary = "false" ] && ! [ $option_connect = "0" ] ; then
echo ''; f_Long; echo "ZONE SERIALS" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
dig +short +nssearch $s | awk '{print "\n\n"$11":\n\n",$1,$2," "$4," >",$13,$14,$15}' | sed 's/^ *//'; fi; fi
echo -e "\n"; f_Long; f_whoisTABLE "$tempdir/rec_ips.list" ; cat $tempdir/whois_table.txt | cut -d '|' -f -5 | sed '/^$/d' | sed '/NET NAME/G'
if [ $domain_enum = "false" ] ; then
asns=$(cut -d '|' -f 1 $tempdir/whois_table.txt | grep -E -v "AS|NA" | sed '/^$/d' | tr -d ' ' | sort -uV)
echo -e "\n___________________________________________________________\n\n"
for as in $asns ; do
asn=$(dig +short as$as.asn.cymru.com TXT | tr -d "\"" | sed 's/^ *//' | cut -d '|' -f 1,5 | sed 's/ |/,/g'); echo -e "AS $asn"; done; echo ''; fi
if [ -f $tempdir/srv ] ; then
echo ''; f_Long; echo -e "\nSRV RECORDS"; echo "$srv_rec"; echo -e "\n__________\n"
cat $tempdir/srv ; rm $tempdir/srv ; fi
if [ -n "$txt_rec" ] ; then
echo ''; f_Long; echo -e "\nTXT RECORDS\n"; echo "$txt_rec" | sed '/\"/{x;p;x;}' | fmt -s -w 80 ; fi
if [ $domain_enum = "false" ] ; then
f_NSEC "${s}"; f_FCRDNS "${s}"; fi
if [ $pmtu = "true" ] ; then
echo''; f_Long; echo "PATH-MTU" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
sudo ${PATH_nmap} -sS -Pn -p 80 --open --resolve-all --script path-mtu $s 2> /dev/null > $tempdir/pmtu; f_PATH_MTU
if [ -f $tempdir/hostsAAAA.list ] ; then
sudo ${PATH_nmap} -6 -sS -Pn -p 80 --open --resolve-all --script path-mtu $s 2> /dev/null > $tempdir/pmtu; f_PATH_MTU; fi
for n in $(dig ns +short $s | rev | cut -c 2- | rev); do
sudo ${PATH_nmap} -sS -Pn -p 53 --open --resolve-all --script path-mtu $n 2> /dev/null > $tempdir/pmtu; f_PATH_MTU
if [ -f $tempdir/ns6.list ] ; then
sudo ${PATH_nmap} -sS -Pn -p 53 --open --resolve-all --script path-mtu $n 2> /dev/null > $tempdir/pmtu; f_PATH_MTU; fi; done
for m in $(dig mx +short $s | rev | cut -d ' ' -f 1 | cut -c 2- | rev); do
if [ -f $tempdir/mx4.list ] ; then
sudo ${PATH_nmap} -sS -Pn -p 25 --open --resolve-all --script path-mtu $m 2> /dev/null > $tempdir/pmtu; f_PATH_MTU; fi
if [ -f $tempdir/mx6.list ] ; then
sudo ${PATH_nmap} -6 -sS -Pn -p 25 --open --resolve-all --script path-mtu $m 2> /dev/null > $tempdir/pmtu; f_PATH_MTU; fi; done; fi
if [ $domain_enum = "false" ] ; then
f_TTL_ALT "${s}"; fi; fi
}
f_MX(){
local s="$*"; dig mx ${dig_array[@]} ${ttl} ${s} > $tempdir/mxservers.list
mxs=$(awk '{print $NF}' $tempdir/mxservers.list) ; echo -e "\n\nMX SERVERS\n"
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
nss=$(awk '{print $NF}' $tempdir/nservers.list); echo -e "\nNAME SERVERS\n"
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
if ! [ $option_connect = "0" ] ; then
if [ $dns_summary = "false" ] ; then
ns_hosts=$(awk '{print $NF}' $tempdir/nservers.list)
for n in $ns_hosts ; do
bindvers=$(dig @${n} version.bind txt chaos +norecurse +noedns +short | tr -d '"' | sed 's/^ *//' |
sed 's/;; connection timed out; no servers could be reached/connection timed out/g' | grep -E -v "^;|^;;" | sed '/^$/d')
if [ -n "$bindvers" ] ; then
echo -e "\n$n" ; echo -e "\t\t\t$bindvers" ; fi ; done > $tempdir/version_bind
if [ -f $tempdir/version_bind ] ; then
echo -e "\n\n\nVERSION.BIND\n"
if [[ $(cat $tempdir/version_bind | wc -w) -lt 2 ]] ; then
echo -e "No response"; else
cat $tempdir/version_bind; fi;  rm $tempdir/version_bind; fi ; fi
echo ''; f_Long; echo -e "\nSTART OF AUTHORITY\n\n"; dig soa +noall +answer +multiline ${s} > $tempdir/soa.txt
dig soa +noall +answer +noclass +ttlid ${s} | awk '{print $2,$3,$4,$5}' | sed 's/ /\t/g' ; echo ''
grep -E "; serial|; refresh|; retry|; expire|; minimum" $tempdir/soa.txt | awk '{print $3":",$1,$4,$5,$6,$7}' | sed 's/:/: /g' |
sed 's/serial:/serial: /' | sed 's/retry:/retry:  /' | sed 's/expire:/expire: /' | sed '/serial:/{x;p;x;G}'; fi
}
f_FCRDNS(){
local s="$*"; echo ''; f_Long; echo "FORWARD CONFIRMED RDNS" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
nmap -Pn -sn -R --script fcrdns 2> /dev/null $s | grep -E "scan report|\||\|_" | sed 's/fcrdns: //g' | sed 's/^|_//g' |
sed 's/^|//g' | sed '/^$/d' | sed '/Nmap scan report/G' | sed 's/Nmap scan report for/\n\n*/g' | sed 's/(/ (/g' | sed 's/FAIL/  FAIL/g'
if [ -f $tempdir/hostsAAAA.list ] ; then
nmap -6 -Pn -sn -R --resolve-all --script fcrdns 2> /dev/null $s | grep -E "scan report|\||\|_"| sed 's/fcrdns: //g' | sed 's/^|_//g' |
sed 's/^|//g' | sed '/^$/d' | sed '/Nmap scan report/G' | sed 's/Nmap scan report for/\n\n*/g' | sed 's/(/ (/g' | sed 's/FAIL/  FAIL/g'; fi
for n in $(dig ns +short $s | rev | cut -c 2- | rev); do
if echo $n | grep -q -E "\.edu\.|\.co\.|\.org.|\.gov\."; then
echo $n | cut -d '/' -f 1 | rev | cut -d '.' -f 1,2,3 | rev >> $tempdir/host_domains; else
echo $n | cut -d '/' -f 1 | rev | cut -d '.' -f 1,2 | rev >> $tempdir/host_domains; fi
nmap -Pn -sn -R --resolve-all --script fcrdns 2> /dev/null $n | grep -E "scan report|\||\|_" | sed 's/fcrdns: //g' | sed 's/^|_//g' |
sed 's/^|//g' | sed '/^$/d' | sed '/Nmap scan report/G' | sed 's/Nmap scan report for/\n\n*/g' | sed 's/(/ (/g' | sed 's/FAIL/  FAIL/g'
if [ -f $tempdir/ns6.list ] ; then
nmap -6 -Pn -sn -R --resolve-all --script fcrdns 2> /dev/null $n | grep -E "scan report|\||\|_" | sed 's/fcrdns: //g' | sed 's/^|_//g' |
sed 's/^|//g' | sed '/Nmap scan report/G' | sed 's/Nmap scan report for/\n\n*/g' | sed 's/(/ (/g' | sed 's/FAIL/  FAIL/g'; fi; done
for m in $(dig mx +short $s | rev | cut -d ' ' -f 1 | cut -c 2- | rev); do
if echo $m | grep -q -E "\.edu\.|\.co\.|\.org.|\.gov\."; then
echo $m | cut -d '/' -f 1 | rev | cut -d '.' -f 1,2,3 | rev >> $tempdir/host_domains; else
echo $m | cut -d '/' -f 1 | rev | cut -d '.' -f 1,2 | rev >> $tempdir/host_domains; fi
if [ -f $tempdir/mx4.list ] ; then
nmap -Pn -sn -R --resolve-all --script fcrdns 2> /dev/null $m | grep -E "scan report|\||\|_" | sed 's/fcrdns: //g' | sed 's/^|_//g' |
sed 's/^|//g' | sed '/^$/d' | sed '/Nmap scan report/G' | sed 's/Nmap scan report for/\n\n*/g' | sed 's/(/ (/g' | sed 's/FAIL/  FAIL/g'; fi
if [ -f $tempdir/mx6.list ] ; then
nmap -Pn -sn -R --resolve-all --script fcrdns 2> /dev/null $m | grep -E "scan report|\||\|_" | sed 's/fcrdns: //g' | sed 's/^|_//g' |
sed 's/^|//g' | sed '/^$/d' | sed '/Nmap scan report/G' | sed 's/Nmap scan report for/\n\n*/g' | sed 's/(/ (/g' | sed 's/FAIL/  FAIL/g'; fi; done; echo ''
}
f_TTL_ALT(){
local s="$*"; echo ''
if [ $option_ttl = "2" ] ; then
ttl_opt="+ttlid"; f_Long ; echo -e "TTL (ms)\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; else
ttl_opt="+ttlunits"; f_Long ; echo -e "TTL - HUMAN READABLE\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; fi
echo -e "\nDOMAIN HOST\t\t\t${s}\n"; dig ${dig_array[@]} ${ttl_opt} $s | grep -w 'A' | awk '{print $2,$3,$4}' | sed 's/ /\t\t/g'
dig aaaa ${dig_array[@]} ${ttl_opt} $s | grep -w 'AAAA' | awk '{print $2,$3,$4}' | sed 's/ /\t\t/g'; echo ''
dig ns ${dig_array[@]} ${ttl_opt} $s | awk '{print $2,$3,$4}' | sed 's/ /\t\t/g'; echo ''
dig mx ${dig_array[@]} ${ttl_opt} $s | awk '{print $2,$3,$5}' | sed 's/ /\t\t/g'; echo ''
}
f_NSEC(){
local s="$*"; echo '' ; f_Long; echo -e "\nNSEC RECORDS\n\n"; f_NSEC_DOMAIN ${s}
if [ $domain_enum = "true" ] ; then
if ! [ "$s" = "$target_host_dom" ] ; then
echo ''; f_NSEC_DOMAIN "${target_host_dom}" ; echo '' ; fi ; fi ; f_NSEC_NS
}
f_NSEC_DOMAIN(){
local s="$*"; host -t nsec ${s} 1.1.1.1 | tail -1 | fmt -s -w 80
host -t nsec3 ${s} 1.1.1.1 | tail -1 | fmt -s -w 80
}
f_NSEC_NS(){
list_nservers=$(awk -F' ' '{print $NF}' $tempdir/nservers.list | sed 's/.$//' | sort -u -V)
for nsurl  in $list_nservers ; do
nsec=$(host -t nsec ${nsurl} 1.1.1.1 | tail -1 | fmt -s -w 80); nsec3=$(host -t nsec3 ${nsurl} 1.1.1.1 | tail -1 | fmt -s -w 80)
echo '' ; echo "$nsec" ; echo "$nsec3" ; done ; echo ''
}
f_DNSdetails(){
local s="$*"; echo ''; egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/mx_ipv4.list | sort -uV > $tempdir/mxip.list
egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/ns_ipv4.list | sort -uV > $tempdir/nsip.list
awk '{print $NF}' $tempdir/mx_ipv6.list | sort -uV > $tempdir/m6.list
awk '{print $NF}' $tempdir/ns_ipv6.list | sort -uV > $tempdir/n6.list
if [ $domain_enum = "false" ] ; then
host $x > $tempdir/hostip; hostA=$(grep "has address" $tempdir/hostip | awk '{print $NF}')
hostAAAA=$(grep "has IPv6 address" $tempdir/hostip | awk '{print $NF}')
if [ -n "$hostA" ] ; then
for a in $hostA ; do
record_type="A"; record_ip="$a"; record_nme="$x"; f_recordINFO "${a}" ; echo '' ; done ; fi
if [ -n "$hostAAAA" ] ; then
for z in $hostAAAA ; do
record_type="AAAA"; record_ip="$z"; record_nme="$x"; f_recordINFO "${z}" ; echo '' ; done ; fi; fi
if ! [ $option_connect = "0" ] && [ $domain_enum = "true" ] ; then
f_Long ; echo "[+]  MX  |  SSL STATUS"
mx_servers=$(cat $tempdir/mx_ipv4.list | awk -F' ' '{print $1}' | sed 's/.$//' | sort -uV)
for m in $mx_servers ; do
f_certINFO "${m}"  ; done; echo ''; fi
if [ -f $tempdir/mx_ipv4.list ] ; then
for mxip in $(cat $tempdir/mxip.list | sort -uV) ; do
mxurl=$(grep ${mxip} $tempdir/mx_ipv4.list | awk -F' ' '{print $1}' | sort -u | tr '[:space:]' ' ' | fmt -s -w 100 ; echo '')
record_type="MX"; record_ip="$mxip"; record_nme="$mxurl"; f_recordINFO "${mxip}" ; echo ''; done; fi
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
if [ -f $tempdir/host_domains ]; then
echo '' > $tempdir/provider_domains; f_Long >> $tempdir/provider_domains
echo -e "[+] DNS RECORDS | SERVICE PROVIDER DOMAINS" >> $tempdir/provider_domains
dnsrec_domains=$(grep -E -v "${s}" $tempdir/host_domains | sort -u)
for d in $dnsrec_domains; do
f_Long; echo -e "$d\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; f_whoisSTATUS "${d}"; f_providerINFO "${d}"; done >> $tempdir/provider_domains; fi
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
sed '/^* /d' > $tempdir/check_zone ; echo -e "NS:\n" ; grep -E -i "name (server|servers)|queries" $tempdir/check_zone |
sed 's/The following servers were found/\n       The following servers were found/g'; echo -e "\nSOA:\n"
grep -E "SOA|Serial" $tempdir/check_zone; echo -e "\nMX:\n" ; grep "MX" $tempdir/check_zone ; echo '' ; f_Long
}
f_AXFR(){
local s="$*" ; f_Long ; echo -e "[+] NS | ZONE TRANSFER | $s" ; f_Long
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
local s="$*" ; echo '' ; f_Long ; echo -e "[+] ${s} | Virtual Hosts"; f_Long; f_BOGON "${s}"
if [ $bogon = "TRUE" ] ; then
echo -e "\nBOGON Address detected [$s]\n"; else
echo ''; curl -s https://api.hackertarget.com/reverseiplookup/?q=${s}${api_key_ht} > $tempdir/vhosts
cat $tempdir/vhosts | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -s -w 80 | sed G; fi
}
f_certMAIL(){
${PATH_nmap} $x -Pn -sn --script hostmap-crtsh 2>/dev/null >> $tempdir/crt_raw
if ! [ "$x" = "$target_host_dom" ] ; then
${PATH_nmap} $target_host_dom -Pn -sn --script hostmap-crtsh 2>/dev/null >> $tempdir/crt_raw ; fi
grep '|' $tempdir/crt_raw | tr -d '|_' | sed '/hostmap-crtsh:/d' | sed '/subdomains:/d' | grep  '\\' | sed 's/\\n/\n/g' |
sed 's/^ *//' | sed 's/^*.//g' | sort -u > $tempdir/crt_results;
if [[ $(cat $tempdir/crt_results | wc -l) -lt 651 ]]; then
cat $tempdir/crt_results >> $tempdir/hosts_raw; fi
certmail=$(grep -s -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/crt_results | sort -u)
if [ -n "$certmail" ] ; then
echo ''; f_Long; echo -e "[+] CERTIFICATE E-MAIL ADDRESSES | SOURCE: crt.sh"; f_Long; echo -e "\n$certmail\n" ; fi
}
f_getSUBS(){
local s="$*"
curl -s https://api.hackertarget.com/hostsearch/?q=${s} | egrep -s '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' >> $tempdir/results_ht
egrep -s -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/results_ht | sort -uV >> $tempdir/ips.list
cut -d ',' -f 1 $tempdir/results_ht | sed 's/^ $//' | tr -d ' ' | sort -u >> $tempdir/hosts_ht
curl -s "https://api.sublist3r.com/search.php?domain=$s" > $tempdir/sublister.json
results_sublister=$(jq -r '.[]' $tempdir/sublister.json | sed '/null/d')
if [ -n "$results_sublister" ] && [[ $(echo "$results_sulbister" | wc -l) -lt 651 ]] ; then
echo "$results_sublister" >> $tempdir/hosts_raw; jq -r '.subdomains[]' $tempdir/tcrowd_$s.json >> $tempdir/hosts_raw ; fi
}
f_subs_HEADER(){
if ! [ $option_connect = "0" ] ; then
f_certMAIL "${x}"; fi; f_getSUBS "${x}"
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
cat $tempdir/table_sorted1 | awk -F '|' '{print $1,$3,$4,$5,$2}' OFS='|' | rev | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n -u |
cut -d '.' -f 3- | rev | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/$/.x.x/g' > $tempdir/whois_table2
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
if [[ $(cat $tempdir/hosts | wc -w) -lt 801 ]]; then
dig @1.1.1.1 +noall +answer +nottlid +noclass -f $tempdir/hosts | sed '/CNAME/d' | sed '/NS/d' |
egrep -s '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' > $tempdir/hosts_res
sed 's/A/,/g' $tempdir/hosts_res | sed 's/^[ \t]*//;s/[ \t]*$//' | awk '{print $3, $2, $1}' | rev |
sed 's/^.//g' | rev | awk '{print $3, $2, $1}' | tr -d ' ' > $tempdir/subs2; fi
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
sed 's/,/\t/g' >> ${outdir}/SUBS.v6.$s.txt ; fi
}
f_DELEGATION(){
local s="$*"; net_ip=$(echo $s | cut -d '/' -f 1)
if ! [ $rir = "lacnic" ] ; then
if [ $rir = "ripe" ] ; then
curl -s "https://stat.ripe.net/data/reverse-dns/data.json?resource=${s}" > $tempdir/revd.json
auth_nameservers=$(jq -r '.data.delegations[]' $tempdir/revd.json | grep -s -A1 'nserver' | tr -d '\":,' |
grep -s 'value' | sed 's/value//' | sed 's/^ *//')
if [ -n "$auth_nameservers" ]; then
echo "$auth_nameservers" >> $tempdir/authns
jq -r '.data.delegations[]' $tempdir/revd.json | grep -s -E -A 1 "domain|descr|nserver|admin-c|zone-c" | tr -d '\":,' |
sed 's/value//g' | sed 's/key//g' | sed 's/^ *//' | sed '/--/d' | sed '/^$/d' | tr '[:space:]' ' ' | sed 's/descr//g' |
sed 's/domain/\n/g' | sed 's/in-addr.arpa/in-addr.arpa\n/g' | sed 's/nserver/\n/g' | sed 's/admin-c/\nadmin-c/g' |
sed 's/zone-c / zone-c;/g' | sed 's/^ *//' | sed '/in-addr.arpa/{x;p;p;x;G}' | sed '/ip6.arpa/{x;p;p;x;G}' |
sed 's/admin-c /admin-c;/g'; else
echo -e "\nNo reverse DNS Zone found for $s"; fi; else
if [[ ${net_ip} =~ $REGEX_IP4 ]] ; then
reverse=$(echo $net_ip | awk -F'.' '{printf $4 "." $3 "." $2}')
if [ $rir = "arin" ] ; then
whois -h whois.arin.net d $reverse.in-addr.arpa. > $tempdir/revd.txt ; else
whois -h whois.$rir.net -- "--no-personal $reverse.in-addr.arpa." > $tempdir/revd.txt ; fi
if [[ $(grep -sEo "NameServer|nserver:" $tempdir/whois | wc -w) = 0 ]]; then
reverse=$(echo $net_ip | awk -F'.' '{printf $4 "." $3}')
if [ $rir = "arin" ] ; then
whois -h whois.arin.net d $reverse2.in-addr.arpa. > $tempdir/revd.txt ; else
whois -h whois.$rir.net -- "--no-personal $reverse2.in-addr.arpa." > $tempdir/revd.txt ; fi; fi
if [[ $(grep -sEo "NameServer|nserver:" $tempdir/whois | wc -w) = 0 ]]; then
echo -e "No reverse DNS delegation found for $reverse2.in-addr.arpa."; else
grep -E "^NameServer:|^nserver:" $tempdir/revd.txt | awk '{print $NF}' | sed 's/^ *//' | tr -d ' ' >> $tempdir/auth_ns
grep -E "^domain:|^descr:|^admin-c:|^zone-c:|^org:|^nserver:|^Name:|NameServer:" $tempdir/revd.txt | sed '/Name:/{x;p;x;G}' |
sed '/domain:/{x;p;x;G}' | cut -d ' ' -f 2- | sed 's/^ *//'; fi; fi ; fi ; fi ; echo ''
}

#********************** NETWORK ENUMERATION - DNS  ***********************
f_nmapSL() {
local s="$*" ; echo '' ; ${PATH_nmap} ${s} -sn -Pn -sL ${dns_servers} 2>/dev/null > $tempdir/nmrdns
grep '(' $tempdir/nmrdns | sed '/Starting Nmap/d' | sed '/Nmap done/d' | sed 's/(/=> /g' | awk '{print $7 "\t\t" $6 "\t" $5}' | tr -d ')'
}
f_NETrDNS() {
local s="$*"
if ! [ $option_netdetails3 = "0" ] ; then
f_Long; echo -e "REVERSE DNS\n\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' ; else
echo -e "\n* Reverse DNS\n" ; fi
if [ $option_source = "3" ] || [ $option_connect = "0" ] ; then
f_RevDNS "${s}" > $tempdir/ipv4_hosts.txt ; else
f_nmapSL "${s}" > $tempdir/ipv4_hosts.txt ; fi
if grep -q -E "\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b" $tempdir/ipv4_hosts.txt; then
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
echo '' ; f_Long; echo -e "\n${B}  Nameservers (System Defaults)${D}" ; f_systemDNS | sed 's/^/  /g'
echo -e "\n\n${B}  Options  >  ${G2}Reverse DNS${B}  >  Sources >\n"
echo -e "${B}  [1] ${G2}NMAP${B} >${D}  default NS  (no max. size)"
echo -e "${B}  [2] ${G2}NMAP${B} >${D}  custom NS  (no max. size)"
echo -e "${B}  [3] ${G2}API${B}  >${D}  hackertarget.com IP API (max. size: /24)"
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

#********************** NETWORK ENUMERATION - LAN  ***********************
f_ARP(){
grep -E "Nmap scan report|Host is|rDNS|MAC Address:" $tempdir/arp  | sed '/scan report/i \_______________________________________________\n' |
sed '/Nmap scan report for/G' | sed 's/Nmap scan report for/*/g' | sed '/Host is up/G' | sed 's/Host is/  Host is/g' |
sed 's/MAC Address:/  MAC Addr: /g' ; echo ''
}
f_DUMP_ROUTER_DHCP_6(){
for if6 in $(cat $tempdir/iflist6 | sort -uV); do
f_Long; echo -e "'DUMP ROUTER6' NIC: $if6\n" | sed -e :a -e 's/^.\{1'',78\}$/ &/;ta'
sudo ${PATH_dump_router6} $if6 | sed 's/^ *//' | sed '/Router:/{x;p;x;G}' | sed '/Options:/{x;p;x;G}' | sed '/MAC:/{x;p;x;}'; echo ''
f_Long; echo -e "'DUMP DHCP66' NIC: $if6\n" | sed -e :a -e 's/^.\{1'',78\}$/ &/;ta'
sudo ${PATH_dump_dhcp6} -N $if6; echo ''; done
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
netabu=$(grep -sEo -m 2 "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/whois.txt | sort -u -V | tr '[:space:]' ' ' ; echo ''); else
netabu=$(grep -sEoi -m 1 "^OrgAbuseEmail:|^% Abuse|^abuse-mailbox:|^e-mail:" $tempdir/whois.txt |
grep -sEo "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b") ; fi
echo -e "\n" ; f_Long ; echo -e "WHOIS  |  $s  |  SERVER:  whois.$rir.net" ; f_Long; echo -e "[@]: $netabu"; echo -e "____\n"
if [ $rir = "lacnic" ] ; then
cat $tempdir/whois.txt | sed '/inetrev:/a \\n__________________________________________________\n' ; else
cat $tempdir/whois.txt | grep -E -a -v "^admin-c:|^mnt-by:|^tech-c:|^fax-no:|^remarks:|^source:" | sed '/^%/d' | sed '/^$/d' |
sed '/NetRange:/{x;p;x;}' | sed '/CIDR:/G' | sed '/Organization:/{x;p;x;}' | sed '/NetName:/{x;p;x;}' | sed '/Updated:/G' |
sed '/OrgAbuseHandle:/i \\n__________________________________________________\n\n' |
sed '/route:/i \\n__________________________________________________\n' | sed '/route6:/i \\n__________________________________________________\n' |
sed '/person:/i \\n__________________________________________________\n' | sed '/role:/i \\n__________________________________________________\n' |
sed '/OrgName:/i \\n__________________________________________________\n' | sed '/netname:/G' |
sed '/OrgNOCHandle:/i \\n__________________________________________________\n' | sed '/^Country:/G' | sed '/^person:/G' | sed '/^role:/G' |
sed '/organisation:/i \\n__________________________________________________\n' | sed '/^org-name/G' | sed '/^route:/G' | sed '/^route6:/G' |
sed '/OrgTechHandle:/i \\n__________________________________________________\n' ; fi
if ! [ $rir = "lacnic" ] && ! [ $rir = "arin" ] ; then
grep -sEa "^admin-c:|^mnt-by:|^tech-c:|^abuse-c:|^mnt-lower:" $tempdir/whois.txt |  tr ':' ';'  | tr -d ' '  > $tempdir/hdl.list
echo -e "__________________________________________________\n" ; echo -e "* $rir OBJECT HANDLES\n\n"
cat $tempdir/hdl.list | sort -uV ; echo -e "\n__________________________________________________\n"
echo -e "* CONTACTS\n\n" ; grep -s -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/whois.txt | sort -f -u
if [[ $(grep -s -a -w -c '^remarks:' $tempdir/whois.txt ) -gt "0" ]] ; then
echo -e "\n__________________________________________________\n"
echo -e "* REMARKS\n\n" ; grep -E "^remarks:" $tempdir/whois.txt ; fi ; fi
}
f_getORGNAME(){
local s="$*"
org_whois=$(grep -Eisa -m 1 "^OrgName:|^org-name:|^owner:" $s | cut -d ':' -f 2- | sed 's/^ *//')
descr=$(grep -Eisa -m 1 "^descr:" $s | cut -d ':' -f 2- | sed 's/^ *//')
if ! [ $target_type = "net" ] || [ $domain_enum = "false" ]; then
if [ $target_type = "default" ] || [ $target_type = "as" ]; then
contact_output=''; else
if [ $rir = "arin" ]; then
org_phone=$(grep -s -i -E "^AbusePhone:|^OrgAbusePhone:" $s | head -1 | cut -d ':' -f 2- | sed 's/^ *//')
contact_output="$org_phone"
elif [ $rir = "lacnic" ]; then
contact_output=''; else
org_phone=$(sed -e '/./{H;$!d;}' -e 'x;/organisation:/!d' $s | grep -sEa "^phone:" | tail -1 | cut -d ':' -f 2- | sed 's/^ *//' | tr -d ' ')
if [ -n "$org_phone" ]; then
contact_output="$org_phone"; else
phone=$(grep -sEa "^phone:" $s | head -1 | cut -d ':' -f 2- | sed 's/^ *//' | tr -d ' '); contact_output="$phone"  ; fi; fi; fi; else
contact_output=''; fi
if [ $target_type = "web" ] || [ $target_type = "default" ]; then
org=$(jq -r '.org' $tempdir/geo.json | sed '/null/d') ; else
org='' ; fi
if [ -n "$org_whois" ] ; then
if [ $rir = "arin" ] ; then
org_cc=$(grep -sEa -m 1 "^Country:" $s | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
org_city=$(grep -sEa -m 1 "^City:" $s | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
orgname=$(grep -sEa -m 1 "^OrgName:" $s | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
orgid=$(grep -sEa -m 1 "^OrgId:" $s | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
if [ $target_type = "hop" ] || [ $target_type = "other" ]; then
org_out="$orgname, $org_city, $org_cc | $contact_output | $orgid"; else
org_out="$orgname,  $org_city, $org_cc ($orgid) $contact_output"; fi
elif [ $rir = "lacnic" ] ; then
org_cc=$(grep -sEa -m 1 "^country:" $s | cut -d ':' -f 2 | sed 's/^ *//')
orgid=$(grep -sEa -m 1 "^owner-c:" $s | cut -d ':' -f 2 | sed 's/^ *//')
orgname=$(grep -sEa -m 1 "^owner:" $s | cut -d ':' -f 2- | sed 's/^ *//')
org_out="$orgname, $org_cc  ($orgid)"; else
if [[ $(sed -e '/./{H;$!d;}' -e 'x;/organisation:/!d' $s | grep -sawc '^country:') -gt "0" ]] ; then
org_cc=$(sed -e '/./{H;$!d;}' -e 'x;/organisation:/!d' $s | grep -sEa -m 1 "^country:" | head -1 | cut -d ':' -f 2- | sed 's/^ *//'); else
org_cc=$(sed -e '/./{H;$!d;}' -e 'x;/organisation:/!d' $s | grep -sEa "^address:" | tail -1 | cut -d ':' -f 2- | sed 's/^ *//'); fi
orgid=$(grep -sEa "^organisation:" $s | cut -d ':' -f 2- | sed 's/^ *//' | head -1)
orgname=$(grep -sEa "^org-name:" $s | cut -d ':' -f 2- | sed 's/^ *//' | head -1)
if [ -n "$orgtype" ] ; then
if [ $target_type = "hop" ] || [ $target_type = "other" ]; then
org_out="$orgname, $org_cc | $contact_output | $orgid | $orgtype"; else
org_out="$orgname, $org_cc ($orgid, $orgtype)   $contact_output"; fi;  else
if [ $target_type = "hop" ] || [ $target_type = "other" ]; then
org_out="$orgname, $org_cc | $contact_output | $orgid"; else
org_out="$orgname, $org_cc ($orgid)   $contact_output"; fi; fi; fi
echo -e "\nOrg:         $org_out" ; else
if ! [ $target_type = "net" ] && [ -n "$descr" ] ; then
echo -e "\nNetDescr:    $descr   $contact_output"
elif ! [ $target_type = "net" ] && [ -n "$org" ] ; then
echo -e "\nOrg:         $org" ; fi ; fi
}
f_ORG(){
local s="$*"
if [[ $(grep -s -c -E "^OrgName:|^Organization:" ${s}) -gt "0" ]] ; then
f_ARIN_ORG "$s"
elif [[ $(grep -s -c -a -E "^organisation:" ${s}) -gt "0" ]] ; then
org_id=$(grep -sEa "^organisation:" ${s} | head -1 | awk '{print $NF}' | sed 's/^ *//')
org_type=$(grep -sEa "^org-type:" $s | head -1 | cut -d ':' -f 2- | sed 's/^ *//'); f_Long
if ! [ $option_detail = "2" ] ; then
echo -e "ORG: $org_id" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
sed -n '/organisation:/,/organisation:/p' ${s} | grep -E -a -m 1 -A 12 "^org-name" > $tempdir/temp
o_name=$(grep -sEa -m 1 "^org-name:" $tempdir/temp | cut -d ':' -f 2- | sed 's/^ *//')
o_addr=$(grep -sEa "^address:" $tempdir/temp | sed '/*\*\*\*\*/d' | cut -d ':' -f 2- | sed 's/^ *//' | tr '[:space:]' ' ')
o_ph=$(grep -sEa -m 1 "^phone:" $tempdir/temp | cut -d ':' -f 2- | sed 's/^ *//')
if [ $target_type = "other" ] ; then
echo -e "$o_name  $o_ph" ; else
echo -e "$o_name"; fi; echo "$org_type" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
if ! [ $target_type = "other" ] ; then
echo -e "$o_ph\n"; fi ; echo -e "$o_addr\n" ; else
echo -e "ORG: $org_id, $org_type" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; whois -h whois.$rir.net -- "-B $org_id" > $tempdir/org_whois
grep -sEa "^org-name:|^role:|^person:|^mntner:|^address:|^e-mail:|^phone:" $tempdir/org_whois | sed '/*\*\*\*\*/d' | sed '/role:/i nnnn' |
sed '/org-name:/i nnn' | sed '/person:/i nnnn' | sed '/role:/a nnn' | sed '/person:/a nnn' | sed '/org-name:/a nnn' | sed '/phone:/i nnn' |
sed '/e-mail:/i nnn' | cut -d ':' -f 2- | sed 's/^ *//' | tr '[:space:]' ' ' | sed 's/nnnn/\n\n\n/g' | sed 's/nnn/\n\n/g' | sed 's/^ *//'; echo ''
fi; fi
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
if [[ $(grep -s -a -w -c '^role:' $tempdir/ac) -gt "0" ]] ; then
sed -e '/./{H;$!d;}' -e 'x;/role:/!d' $tempdir/ac | grep -E -a "^role:|^address:|^phone:|^nic-hdl:" |
sed '/role:/a nnnn' | sed '/role:/i nnn' | sed '/phone:/i nnn' | sed '/e-mail:/i nnn' | sed '/nic-hdl:/i nnn' |
sed '/nic-hdl:/a nnn' | cut -d ':' -f 2- | sed 's/^ *//' | tr '[:space:]' ' ' | sed 's/nnn /\n/g' | sed 's/nnnn/\n\n/g' | sed 's/^ *//'; echo '' ; fi
if [[ $(grep -s -a -w -c '^person:' $tempdir/ac) -gt "0" ]] ; then
sed -e '/./{H;$!d;}' -e 'x;/person:/!d' $tempdir/ac | grep -E -a "^person:|^address:|^phone:|^e-mail:|^nic-hdl:" |
sed '/person:/a nnnn' | sed '/person:/i nnn' | sed '/phone:/i nnn' | sed '/e-mail:/i nnn' | sed '/nic-hdl:/i nnn' |
sed '/nic-hdl:/a nnn' | cut -d ':' -f 2- | sed 's/^ *//' | tr '[:space:]' ' ' | sed 's/nnn /\n/g' |
sed 's/nnnn/\n\n/g' | sed 's/^ *//'; echo ''; fi; fi
}

#********************** NETWORK ENUMERATION - WHOIS  ***********************
f_whoisNET(){
local s="$*" ; query="$s"; export query ; net_ip=$(echo $s | cut -d '/' -f 1) ; echo '' ; f_getRIR "${s}"
if [ $rir = "ripe" ] && [[ ${net_ip} =~ $REGEX_IP4 ]]; then
curl -s -m 7 "https://stat.ripe.net/data/address-space-usage/data.json?resource=${s}" > $tempdir/space_usage.json; fi
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
local s="$*"; cidrs=$(${PATH_ipcalc} -r $s | sed '/deaggregate/d')
if [[ $(echo "$cidrs" | wc -w) = 1 ]] && [ "$cidrs" = "$net_resource" ] ; then
${PATH_ipcalc} -b -n ${cidrs} > $tempdir/ipcal; hosts=$(grep 'Hosts/Net' $tempdir/ipcal | awk '{print $2}')
echo -e "Netmask:     $(grep 'Netmask' $tempdir/ipcal | awk '{print $2}'), $(grep 'Wildcard:' $tempdir/ipcal | awk '{print $NF}')   $hosts hosts\n"; else
for i in $cidrs ; do
${PATH_ipcalc} -b -n ${i} > $tempdir/ipcal
hosts=$(grep 'Hosts/Net' $tempdir/ipcal | awk '{print $2}')
mask=$(grep 'Netmask' $tempdir/ipcal | awk '{print $2}')
if [ -n "$hosts" ] ; then
echo -e "             $i  ($mask,  $hosts hosts)\n"; rm $tempdir/ipcal; fi ; done; fi
}
f_sipCALC(){
local s="$*"; if [ -n "${PATH_sipcalc}" ]; then
address_id=$(${PATH_sipcalc} ${s} | grep -E "^Address ID" | awk '{print $NF}')
address_type=$(${PATH_sipcalc} ${s} | grep -E "^Address type" | awk -F'-' '{print $NF}' | sed 's/^ *//')
if ! [ $rir = "arin" ]; then
v6_range=$(${PATH_sipcalc} ${s} | grep -E -A 1 "^Network range" | cut -d '-' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' '; echo '')
echo -e "\nRange:       $v6_range\n"; fi
if ! [[ ${address_type} =~ "Global Unicast Addresses" ]] ; then
echo -e "Type:        $address_type\n"; fi; fi
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
as=$(jq -r '.data.asns[0].asn' $tempdir/pov.json); export as; fi
curl -s "https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource=${geo_target}" > $tempdir/netgeo.json
netgeo=$(jq -r '.data.located_resources[].locations[] | .country' $tempdir/netgeo.json | sort -u | tr '[:space:]' ' ' ; echo '')
if [ -n "$net_resource" ]; then
if [ -n "$net_status" ]; then
if [ $rir = "ripe" ] && [[ ${net_ip} =~ $REGEX_IP4 ]] && [[ $net_status =~ "ALLOCATED" ]]; then
echo -e "\nNet:         $net_name  | $net_resource | $rir_caps | $created"
echo -e "\n             $net_status | Assignments: $(jq '.data.allocations[].assignments' $tempdir/space_usage.json)\n"; else
echo -e "\nNet:         $net_name  | $net_resource | $rir_caps"
echo -e "\n             $net_status | $created\n" ; fi ; else
echo -e "\nNet:         $net_name  | $n_resource | $created | $rir_caps" ; fi ; else
if [ -n "$net_status" ] ; then
echo -e "\nNet:         $net_name  | $created | $net_status | $rir_caps"; else
echo -e "\nNet:         $net_name  | $net_resource | $created | $rir_caps" ; fi ; fi
if ! [[ ${net_ip} =~ $REGEX_IP4 ]]; then
if [ $rir = "arin" ] ; then
echo -e "\n\nRange:       $net_range\n" ; fi; f_sipCALC "${s}"; fi
if [[ ${net_ip} =~ $REGEX_IP4 ]] ; then
echo -e "\nRange:       $net_range\n"; f_ipCALC "${range_trimmed}"; fi
if [ -n "$cidr" ] && ! [ $cidr = "$net_resource" ] ; then
echo -e "CIDR:        $cidr\n" ; fi
if [[ $(echo "$netgeo" | wc -w ) -lt 22 ]]; then
echo -e "\nGeo:         $ctry (whois), $netgeo (maxmind)"; fi
if [ -n "$descr" ] ; then
echo -e "\nDescr:       $descr" ; fi
if [ $rir = "ripe" ] && [[ ${net_ip} =~ $REGEX_IP4 ]] && [[ $net_status =~ "ASSIGNED" ]] ; then
p_alloc=$(jq -r '.data.allocations[0].allocation' $tempdir/space_usage.json | sed '/null/d')
if [ -n "$p_alloc" ]; then
parent=$(jq '.data.allocations[] | {alloc: .allocation, name: .asn_name, status: .status}' $tempdir/space_usage.json | tr -d '},"{' | sed 's/^ *//' |
sed '/^$/d' | tr '[:space:]' ' ' | sed 's/alloc: //' | sed 's/name:/|/g' | sed 's/status:/|/')
num_hosts=$(${PATH_ipcalc} -b -n ${p_alloc} | grep 'Hosts/Net' | awk '{print $2}' | tr -d ' ')
echo -e "\n\nParent:      $parent | max. hosts: $num_hosts"; fi; fi
if [ -f $tempdir/pov2.json ]; then
echo ''; fi
echo -e "\nPrefix:      $resource | announced: $announced | related prefixes: $num_related"
if [ -f $tempdir/pov2.json ]; then
resource_query=$(jq -r '.data.resource' $tempdir/pov2.json)
if ! [ "$resource" = "$resource_query" ] ; then
announced_query=$(jq -r '.data.announced' $tempdir/pov2.json)
echo -e "\n             $resource_query | announced: $announced_query"; fi ; fi
if [ $option_detail = "2" ] && [ $target_type = "net" ]; then
f_getORGNAME "$tempdir/whois"; fi
if [[ $(echo "$netgeo" | wc -w ) -gt 21 ]]; then
echo ''; f_Long ; echo "LOCATION" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
echo -e "Country (whois):\n"; echo -e "$ctry"
if [ $target_type = "net" ]; then
echo -e "\nGeolocation (maxmind):\n"; else
echo -e "\nNetwork Geolocation (maxmind):\n"; fi
echo "$netgeo" | fmt -w 60; fi; echo ''
if [ $target_type = "net" ] ; then
query="$s"; export query
if [ $rir = "arin" ]; then
echo ''; f_ORG "$tempdir/whois" ; else
if [ $option_detail = "1" ] || [ $option_detail = "3" ]; then
echo ''; f_ORG "$tempdir/whois"
ac=$(grep -E "^admin-c:" $tempdir/whois | cut -d ':' -f 2- | sed 's/^ *//' | head -1); f_Long; f_ADMIN_C "${ac}" ; else
f_getWHOIS "${s}" ; f_POC "$tempdir/whois.txt" ; fi; fi ; echo ''
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
f_RELATED "${s}" ; echo '' ; f_ROUTE_CONS "${s}"; echo ''; f_Long; f_NETGEO "${s}" ; fi
if ! [ $option_netdetails1 = "0" ] && ! [ $rir = "lacnic" ]; then
if [ -n "$net_name" ] ; then
echo ''; f_netRESOURCES "${net_name}" ; fi; fi
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
echo ''; f_Long; echo -e "BANNERS\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
f_BANNERS "${s}" ; fi
if [ $option_netdetails2 = "2" ] || [ $option_netdetails2 = "3" ]; then
f_Long ; echo "WHOIS-REV.DNS CONSISTENCY" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
if [ $rir = "ripe" ]; then
f_rdnsCONS "${s}" > $tempdir/dns_cons
complete=$(grep 'complete:' $tempdir/dns_cons | grep 'true' | sed '/complete:/G')
if [ -n "$complete" ]; then
echo -e "$complete"; else
grep 'complete:' $tempdir/dns_cons | sed '/complete:/{x;p;x;G}'
incomplete=$(grep -v 'complete:' $tempdir/dns_cons | grep 'false')
if [ -n "$incomplete" ]; then
echo -e "WHOIS entries missing for zones:\n"
echo "$incomplete" | awk -F'>' '{print $1}' ; echo '' ; fi ; fi
echo ''; f_Long; echo "REV. DNS LOOKUP ZONES" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
f_DELEGATION "${s}"; else
echo -e "\nOption not available for non-RIPE-managed address space\n" ; fi ; fi
}
f_NET_HEADER(){
local s="$*" ; net_ip=$(echo $s | cut -d '/' -f 1)
asn=$(curl -s "https://stat.ripe.net/data/network-info/data.json?resource=${s}" | jq -r '.data.asns[0]')
if [[ ${net_ip} =~ $REGEX_IP4 ]]; then
reg=$(curl -s "https://stat.ripe.net/data/rir/data.json?resource=${s}" | jq -r '.data.rirs[0].rir' | cut -d ' ' -f 1 | tr -d ' ' |
tr [:upper:] [:lower:]); else
curl -s "https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=${s}" > $tempdir/ac.json
reg=$(jq -r '.data.authoritative_rir' $tempdir/ac.json); fi
if [ $reg = "arin" ]; then
whois -h whois.arin.net $s > $tempdir/whois.txt
range=$(grep -a -E "^CIDR:" $tempdir/whois.txt | cut -d ' ' -f 2- | sed 's/^ *//' | head -3 | tr '[:space:]' ' '; echo '')
elif [ $reg = "lacnic" ]; then
whois -h whois.lacnic.net $s > $tempdir/whois.txt; else
whois -h whois.$reg.net -- "-r -F $s" | tr -d '*' | sed 's/^ *//' > $tempdir/whois.txt; fi
netn=$(grep -s -a -i -E -m 1 "^netname:|^na:" $tempdir/whois.txt | cut -d ' ' -f 2- | sed 's/^ *//')
range=$(grep -s -a -i -E -m 1 "^netrange:|^in:" $tempdir/whois.txt | cut -d ' ' -f 2- | tr -d ' ' | sed 's/^ *//')
whois_cc=$(grep -E -i -a -m 1 "^country:|^cy:" $tempdir/whois.txt | cut -d ' ' -f 2- | sed 's/^ *//')
hostnum=$(ipcalc -b -n ${x} | grep -s -E "^Hosts/Net" | cut -d ':' -f 2 | sed 's/Class.*//' | tr -d ' ')
if [ $reg = "lacnic" ] ; then
netabu=$(grep -E -o -m 2 "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/whois.txt | sort -u -V | tr '[:space:]' ' ' ; echo ''); else
netabu=$(grep -E -i -m 1 "^OrgAbuseEmail:|^% Abuse|^abuse-mailbox:|^e-mail:" $tempdir/whois.txt |
grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b") ; fi
echo ''; f_Long; echo -e "$x, $hostnum hosts | $whois_cc | AS $asn | $file_date"; f_Long
echo -e "[@]: $netabu | $netn - $range" ; echo -e "____\n"
}
f_POC(){
local s="$*"
if [ $rir = "arin" ] ; then
echo ''; f_ORG "$s"; else
if [[ $(grep -E -a "^organisation:" $s | wc -l) -gt 0 ]] ; then
org_id=$(grep -E -a "^organisation:" ${s} | head -1 | awk '{print $NF}' | sed 's/^ *//')
if [ $target_type = "as" ]; then
org_type=$(grep -sEa "^org-type:" $s | head -1 | cut -d ':' -f 2- | sed 's/^ *//')
echo ''; f_Long; echo -e "ORG: $org_id ($org_type\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; else
echo ''; f_Long; echo -e "ORG: $org_id\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; fi; else
echo ''; f_Long; echo "CONTACT" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; fi
if [[ $(grep -s -w -c '^org-name:' $s ) -gt "0" ]] ; then
echo '' ; sed -e '/./{H;$!d;}' -e 'x;/organisation:/!d' $s | sed -n '/organisation:/,/organisation:/p' |
grep -E -a -s "^org-name:|^address:|^phone:|^e-mail:" | sed '/*\*\*\*\*/d' | sed '/org-name:/a nnn' | sed '/phone:/i nnn' | sed '/e-mail:/i nnn' |
cut -d ':' -f 2- | sed 's/^ *//' | tr '[:space:]' ' ' | sed 's/nnn /\n/g' ; echo '' ; fi
if [[ $(grep -s -w -c '^role:' $s ) -gt "0" ]] ; then
if [ $target_type = "as" ]; then
sed -e '/./{H;$!d;}' -e 'x;/role:/!d' $s | grep -Eisa -v "^created:|last-modified:|^fax-no:|^source" | sed '/role:/i nnnn' |
sed '/*\*\*\*\*/d' | sed '/address:/i nnn' | sed '/e-mail:/i nnn' | sed '/phone:/i nnn' | sed '/nic-hdl:/i nnn' | sed '/mnt-by:/i nnn' |
cut -d ':' -f 2- | sed 's/^ *//' | tr '[:space:]' ' ' | sed 's/nnnn/\n\n/g' | sed 's/nnn/\n/g' | sed 's/^ *//'; echo ''; else
sed -e '/./{H;$!d;}' -e 'x;/role:/!d' $s | grep -E -a "^role:|^address:|^phone:|^nic-hdl:" | sed '/*\*\*\*\*/d' |
sed '/role:/a nnn' | sed '/role:/i nnn' | sed '/phone:/i nnn' | sed '/e-mail:/i nnn' | sed '/nic-hdl:/i nnn' |
sed '/nic-hdl:/a nnn' | cut -d ':' -f 2- | sed 's/^ *//' | tr '[:space:]' ' ' | sed 's/nnn /\n/g'
sed -e '/./{H;$!d;}' -e 'x;/role:/!d' $s | grep -a -s "^nic-hdl" | sed '/^$/d' |
cut -d ':' -f 2- | sed 's/^ *//' >> $tempdir/nic_hdls; fi
if [[ $(grep -s -w -c '^person:' $s ) -gt "0" ]] ; then
echo '' ;fi; fi
if [[ $(grep -s -w -c '^person:' $s ) -gt "0" ]] ; then
if [ $target_type = "as" ]; then
sed -e '/./{H;$!d;}' -e 'x;/person:/!d' ${s} | grep -Eisa -v "^created:|last-modified:|^fax-no:|^source" | sed '/person:/i nnnn' | sed '/*\*\*\*\*/d' |
sed '/address:/i nnn' | sed '/e-mail:/i nnn' | sed '/phone:/i nnn' | sed '/nic-hdl:/i nnn' | sed '/mnt-by:/i nnn' | cut -d ':' -f 2- |
sed 's/^ *//' | tr '[:space:]' ' ' | sed 's/nnnn/\n\n/g' | sed 's/nnn/\n/g' | sed 's/^ *//'; echo ''; else
sed -e '/./{H;$!d;}' -e 'x;/person:/!d' $s | grep -E -a "^person:|^address:|^phone:|^e-mail:|^nic-hdl:" | sed '/*\*\*\*\*/d' |
sed '/person:/a nnn' | sed '/person:/i nnn' | sed '/phone:/i nnn' | sed '/e-mail:/i nnn' | sed '/nic-hdl:/i nnn' |
sed '/nic-hdl:/a nnn' | cut -d ':' -f 2- | sed 's/^ *//' | tr '[:space:]' ' ' | sed 's/nnn /\n/g'
sed -e '/./{H;$!d;}' -e 'x;/person:/!d' $s | grep -a -s "^nic-hdl" | sed '/^$/d' |
cut -d ':' -f 2- | sed 's/^ *//' >> $tempdir/nic_hdls ; fi; fi
grep -E "^organisation" $s | sed 's/organisation:/org:/' | tr ':' ';' | tr -d ' ' | sort -uV > $tempdir/whois_objects
grep -E "^mnt-by:|^mnt-lower:|^mnt-ref:" $s | sed '/RIPE-NCC-*/d' | tr ':' ';' | tr -d ' ' | sort -uV >> $tempdir/whois_objects
grep -E "^abuse-c:|^admin-c:|tech-c:" $s  | tr ':' ';' | tr -d ' ' | sort -uV >> $tempdir/whois_objects
if [ $target_type = "as" ]; then
echo ''; grep -s -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/whois_as > $tempdir/as_mail
jq -r '.data.email_contacts[]?' $tempdir/asn.json >> $tempdir/as_mail
grep -s -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $s >> $tempdir/as_mail; cat $tempdir/as_mail | sort -u; else
net_mail=$(grep -s -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $s | sort -u)
if [[ $(echo "$net_mail" | wc -w) -gt 1 ]]; then
f_Short; echo ''; echo "$net_mail" | tr '[:space:]' ' ' | sed 's/ /  /g' | fmt -s -w 70 | sed G; else
echo -e "$net_mail"; fi; fi; f_Short
cat $tempdir/whois_objects | tr '[:space:]' ' ' | fmt -s -w 70; echo ''; fi
}
f_netRESOURCES(){
local s="$*" ; echo '' ; f_Long
echo "RESOURCES FOR '$s'" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
if [ $rir = "arin" ] ; then
whois -h whois.arin.net -- "n . + > $s" | sed '/#/d' | sed '/^$/d' > $tempdir/netwho_raw
netcount=$(grep -E "^NetRange:" $tempdir/netwho_raw | wc -l); echo -e "Networks: $netcount\n"
grep -E "^NetRange:|^CIDR:|^NetHandle:|^Organization:|^City:|^Country:|^OrgAbuseEmail:" $tempdir/netwho_raw |
sed 's/NetRange:       /NetRange /g' | sed 's/CIDR:           /CIDR /g' | sed 's/NetHandle:      /Handle /g' | sed 's/Organization:   /Org /g' |
sed 's/City:           /City /g' | sed 's/Country:        /Ctry /g' | tr '[:space:]' ' ' | sed 's/NetRange /\n\n\n/g' | sed 's/CIDR/|/g' |
sed 's/Handle/|/g' | sed 's/City/|/g' | sed 's/Ctry/|/g' | sed 's/OrgAbuseEmail:  /AM /g' | sed 's/AM/|/g' | sed 's/Org / \n/g' |
fmt -s -w 80 | sed '/|/G' > $tempdir/netwho
if [[ $netcount -lt "26" ]] ; then
cat $tempdir/netwho ; else
echo -e "Output has been written to file."
echo '' > $outdir/NetRanges.$s.txt; f_Long >> $outdir/NetRanges.$s.txt
echo "RESOURCES FOR '$s' ($rir)" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' >> $outdir/NetRanges.$s.txt
cat $tempdir/netwho >> $outdir/NetRanges.$s.txt ; fi ; fi
if ! [ $rir = "lacnic" ] && ! [ $rir = "arin" ] ; then
if [ -f $tempdir/whois.txt ] ; then
sed -e '/./{H;$!d;}' -e 'x;/person:/!d' $tempdir/whois.txt | grep -Eas "^nic-hdl" | cut -d ':' -f 2- |
sed 's/^ *//' >> $tempdir/nic_hdls
sed -e '/./{H;$!d;}' -e 'x;/role:/!d' $tempdir/whois.txt | grep -Eas "^nic-hdl" | cut -d ':' -f 2- |
sed 's/^ *//' >> $tempdir/nic_hdls
elif [ -f $tempdir/whois ] ; then
grep -Eas "^admin-c:|^nic-hdl:" $tempdir/whois | awk '{print $NF}' > $tempdir/nic_hdls
if [ -f $tempdir/ac ]; then
grep -Eas "^ac:|^nh:" $tempdir/whois | awk '{print $NF}' >> $tempdir/nic_hdls; fi; fi
cat $tempdir/nic_hdls | tr -d ' ' | sed '/^$/d' | sort -uV > $tempdir/nh_list1
whois -h whois.$rir.net -- "-F $s" | tr -d '*' | sed 's/^ *//' > $tempdir/netwho_raw
if [[ $(grep -s -E -c "^in:" $tempdir/netwho_raw) -gt "0" ]] ; then
sed -e '/./{H;$!d;}' -e 'x;/in:/!d' $tempdir/netwho_raw | grep -E "^in:|^cy:|^ac:" | sed '/in:/{x;p;x;}' > $tempdir/netwho4_raw
cat $tempdir/netwho4_raw | sed 's/cy:/ |/g' | sed 's/ac: / | admin-c;/g' | tr '[:space:]' ' ' | sed 's/in:/\n/g' |
sed 's/^ *//' | cut -d '|' -f -3 | sed '/|/G' > $tempdir/netwho ; fi
if [[ $(grep -s -E -c "^i6:" $tempdir/netwho_raw) -gt "0" ]] ; then
sed -e '/./{H;$!d;}' -e 'x;/i6:/!d' $tempdir/netwho_raw | grep -E "^i6:|^cy:|^ac:" | sed '/i6:/{x;p;x;}' > $tempdir/netwho6_raw
cat $tempdir/netwho6_raw | sed 's/cy:/ |/g' | sed 's/ac: / | admin-c;/g' | tr '[:space:]' ' ' | sed 's/i6:/\n/g' |
sed 's/^ *//' | cut -d '|' -f -3 > $tempdir/netwho6 ; fi
if [ -f $tempdir/netwho ]; then
cat $tempdir/netwho | awk -F'admin-c;' '{print $2}' | sed 's/^ *//' | sed '/^$/d' | tr -d ' ' > $tempdir/nh_list2; fi
if [ -f $tempdir/netwho6 ]; then
cat $tempdir/netwho6 | awk -F'admin-c;' '{print $2}' | sed 's/^ *//' | sed '/^$/d' | tr -d ' ' >> $tempdir/nh_list2; fi
sort -uV $tempdir/nh_list2 > $tempdir/nh_list2_sorted
admins_other=$(diff --suppress-common-lines --ignore-all-space $tempdir/nh_list1 $tempdir/nh_list2_sorted | grep '>' | cut -d ' ' -f 2 | head -12)
nets=$(grep -E "^in:" $tempdir/netwho_raw | cut -d ':' -f 2- | sed 's/^ *//' | egrep '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | tr -d ' ')
netcount=$(echo "$nets" | wc -w)
v6nets=$(grep -E "^i6:" $tempdir/netwho_raw | cut -d ' ' -f 2- | sed 's/^ *//'); netcount6=$(echo "$v6nets" | wc -w)
if [[ $netcount -gt "2" ]] || [[ $netcount6 -gt "2" ]]; then
if [[ $netcount6 -gt "0" ]]; then
echo -e "\nIPv6 Networks:  $netcount6"; fi
if [[ $netcount -gt "0" ]]; then
echo -e "\nIPv4 Networks:  $netcount"; fi; fi
if [[ $netcount6 -gt "0" ]] ; then
if [[ $netcount6 -lt "26" ]] ; then
echo ''; cat $tempdir/netwho6 | sed '/|/G' ; else
echo -e "\nIPv6 Resources: Output has been written to file.\n" ; cat $tempdir/netwho6 >> $outdir/NetRanges6.$s.txt ; fi; fi
if [[ $netcount -gt "0" ]]; then
echo '' > $tempdir/resources_v4
cat $tempdir/netwho >> $tempdir/resources_v4
if [[ $netcount -gt "1" ]] ; then
f_Shorter >> $tempdir/resources_v4  ; fi
for n in $(cat $tempdir/netwho_raw | grep "^in:" | cut -d ':' -f 2- | sed 's/^ *//' | egrep '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | tr -d ' ');do
${PATH_ipcalc} "${n}" | sed '/deaggregate/d' | sed '/^$/d'; done > $tempdir/ranges
cat $tempdir/ranges | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -s -w 40 >> $tempdir/resources_v4
echo '' >> $tempdir/resources_v4
if [[ $netcount -lt "26" ]] ; then
cat $tempdir/resources_v4 ; else
echo -e "\nIPv4 Resources: Output has been written to file\n" ; cat $tempdir/resources_v4 >> $outdir/NetRanges4.$s.txt ; fi ; fi
if [ -n "$admins_other" ] ; then
f_Long; echo -e "CONTACTS" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
for i in $admins_other ; do
whois -h whois.$rir.net -- "-r -F $i" | tr -d '*' | sed 's/^ *//' > $tempdir/acwhois
sed -e '/./{H;$!d;}' -e 'x;/pn:/!d' $tempdir/acwhois | grep -E -a -s "^pn:|^ad:|^cy:|^ph:|^mb:|^nh:" |
sed '/pn:/{x;p;x;}' | cut -d ':' -f 2- | sed 's/^ *//'
sed -e '/./{H;$!d;}' -e 'x;/ro:/!d' $tempdir/acwhois | grep -E -a -s "^ro:|^ad:|^cy:|^ph:|^mb:|^nh:" |
sed '/ro:/{x;p;x;}' | cut -d ':' -f 2- | sed 's/^ *//' ; done ; fi ; fi;
}
f_domainNETS(){
local s="$*" ; net_ip=$(echo $s | cut -d '/' -f 1) ; echo '' >> $tempdir/domain_nets ; f_getRIR "${s}"
if ! [ $rir = "lacnic" ] ; then
if [ $rir = "arin" ] ; then
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
echo -e "\n$created | $ctry | $rir_caps | $allocation_status | $pfx | AS $asn" >> $tempdir/domain_nets
f_POC "$tempdir/whois.txt" >> $tempdir/domain_nets ; f_netRESOURCES "${netname}" >> $tempdir/domain_nets
echo '' >> $tempdir/domain_nets; fi ; fi
}
f_NETGEO(){
local s="$*"; net_ip=$(echo $s | cut -d '/' -f 1)
if ! [ -f $tempdir/netgeo.json ] ; then
curl -s https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource=${s} > $tempdir/netgeo.json ; fi
jq -r '.data.located_resources[].locations | .[] | .resources[]' $tempdir/netgeo.json | sort -u -V > $tempdir/nets_geo.list
netcount=$(cat $tempdir/nets_geo.list | wc -w); locations=$(jq -r '.data.located_resources[].locations | .[]' $tempdir/netgeo.json)
echo -e "GEOGRAPHIC DISTRIBUTION\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' | tee $tempdir/geo_temp1
echo "$locations" | jq -r '{N: .resources[], Lat: .latitude, Lon: .longitude, cov: .covered_percentage, Country: .country, C: .city}' |
tr -d '{,"}' | sed 's/^ *//' | sed '/^$/d' | tr '[:space:]' ' ' | sed 's/N: /\n\n/g' | sed 's/ Lon: /\,/g' | sed 's/Lat:/ -  Lat\/Lon:/g' |
sed 's/cov:/(covered:/g' | sed 's/Country:/%) | Country:/g' | sed 's/C://g' >> $tempdir/geo_temp2 ; echo '' >> $tempdir/geo_temp2
if [[ $netcount -gt "3" ]] ; then
echo -e "\n_______________________________________\n" >> $tempdir/geo_temp2
cat $tempdir/nets_geo.list | tr '[:space:]' ' ' | fmt -s -w 40 | sed 's/ /  /g' | sed 's/^ *//' >> $tempdir/geo_temp2
echo '' >> $tempdir/geo_temp2 ; fi
if [[ $netcount -gt 51 ]] ; then
echo -e "\nOutput has been written to file ($netcount networks)" ; f_Long > $outdir/NET_GEOLOC.$net_ip.txt
echo '' > $outdir/NET_GEOLOC.$net_ip.txt; cat $tempdir/geo_temp1 >> $outdir/NET_GEOLOC.$net_ip.txt
cat $tempdir/geo_temp2 >> $outdir/NET_GEOLOC.$net_ip.txt ; else
cat $tempdir/geo_temp2; fi ; rm $tempdir/netgeo.json
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
if [[ $subnets_total -lt 81 ]] ; then
cat $tempdir/subnets; else
echo -e "\nSubnets: Results have been written to file\n" ; cat $tempdir/subnets > ${outdir}/SUBNETS.$net_ip.txt ; fi; fi; fi
}
f_addressSPACE(){
local s="$*" ; net_ip=$(echo "$s" | cut -d '/' -f 1)
f_getRIR "${s}"
if ! [ $rir = "arin" ] && ! [ $rir = "lacnic" ] ; then
whois -h whois.$rir.net -- "-x $s" > $tempdir/exact
cat $tempdir/exact |
grep -i -E "^inetnum:|^inet6num:|^netname:|^org:|^org-name:|^descr:|^country:|^admin-c:" | sed '/inetnum:/{x;p;x;G}' | sed '/inet6num:/{x;p;x;G}'; echo ''
whois -h whois.$rir.net -- "-r -F -M $s" | tr -d '%*' | sed 's/^ *//' > $tempdir/whois | grep -E -a  "^in:|^i6:|^na:" > $tempdir/whois
if [ $option_filter = "y" ] ; then
for f in $(cat $tempdir/filters) ; do
echo '' ; f_Long ; echo -e "MORE SPECIFICS, FILTER: $filter\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
cat $tempdir/whois | grep -E -a  "^in:|^i6:|^na:" |
grep -s -a -i -E -B 1 "${f}|*.${f}.*|${f}NET|*.-${f}.-*|${f}-.*|*-.${f}|${f}AS" > $tempdir/whois_filtered
filtered=$(cat $tempdir/whois_filtered | sed '/^$/d' | sed '/in:/{x;p;x;}' | sed '/i6:/{x;p;x;}' | sed '/--/d' | cut -d ' ' -f 2- | sed 's/^ *//')
if [ -n "$filtered" ] ; then
echo "$filtered" ; echo ''; f_Long ; echo -e "* CIDR\n"
cat $tempdir/whois_filtered | grep -E -i "^i6:" $tempdir/whois_filtered | cut -d ' ' -f 2- | tr -d ' ' | fmt -s -w 20
for i in $(cat $tempdir/whois_filtered | grep "^in:" | grep -E "\-" | cut -d ' ' -f 2- | tr -d ' ') ; do
${PATH_ipcalc} ${i} | sed '/deaggregate/d' ; done ; else
echo -e "\nNo results" ; fi ; done; echo '' ; else
echo '' ; f_Long ; echo "MORE SPECIFICS" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
cat $tempdir/whois | grep -E -a "^in:|^i6:|^na:|^de:|^og:|^or:|^rt:|^r6:|^ac:|^cy:" | sed '/in:/G' | sed '/i6:/G' |
sed '/in:/i \\n__________________________________\n' | sed '/i6:/i \\n__________________________________\n' |
sed '/rt:/i \\n__________________________________\n' | sed '/r6:/i \\n__________________________________\n' |
sed '/--/d' | cut -d ' ' -f 2- | sed 's/^ *//'; echo ''; f_Long ; echo -e "* CIDR\n"
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
whois -h whois.arin.net -- "e + $s" > $tempdir/whois; mail_dom=$(echo $s | cut -d '@' -f 2); f_DNSWhois_STATUS "${mail_dom}" ; else
whois -h whois.arin.net "z + > $s" > $tempdir/whois ; fi
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
f_ARIN_NET(){
local s="$*"
grep -E "^NetRange:|^CIDR:|^NetHandle:|^Organization:|^City:|^Country:|^OrgAbuseEmail:" ${s} |
sed 's/NetRange:       /NetRange /g' | sed 's/CIDR:           /CIDR /g' | sed 's/NetHandle:      /Handle /g' | sed 's/Organization:   /Org /g' |
sed 's/City:           /City /g' | sed 's/Country:        /Ctry /g' | tr '[:space:]' ' ' | sed 's/NetRange /\n\n\n/g' | sed 's/CIDR/|/g' |
sed 's/Handle/|/g' | sed 's/City/|/g' | sed 's/Ctry/|/g' | sed 's/OrgAbuseEmail:  /AM /g' | sed 's/AM/|/g' | sed 's/Org / \n/g' |
fmt -s -w 80 | sed '/|/G'
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
echo -e "\nGeo:         $netgeo (maxmind)\n"
f_Long; echo "OWNER" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
grep -E -A 10 "^owner:" $tempdir/whois | grep -E -a "^owner:|^owner-c:|^country:" | sed '/owner:/i nnn' | sed '/country:/i ,' | sed '/owner-c:/i (' |
sed '/owner-c:/a )' | cut -d ' ' -f 2- | sed 's/^ *//' | tr '[:space:]' ' ' | sed 's/nnn/\n\n/g' | sed 's/^ *//' | sed 's/ ,/,/g' | sed 's/( / (/' |
sed 's/ )/)/' ; echo ''
responsible=$(grep -E "^responsible" $tempdir/whois | cut -d ' ' -f 2- | sed 's/^ *//')
echo -e "\nResponsible: $responsible"
sed -n '/person:/,$p' $tempdir/whois | grep -E -a "^person:|^e-mail:|^country" | sed '/person:/i nnn' | sed '/e-mail:/i:' |
sed '/country:/i ,' | cut -d ' ' -f 2- | sed 's/^ *//' | tr '[:space:]' ' ' | sed 's/nnn/\n\n/g' | sed 's/^ *//' |
sed 's/ :/: /g' | sed 's/ ,/,/g'  ; echo -e "\n"
nsservers=$(grep -E "nserver:" $tempdir/whois | awk '{print $NF}' | tr '[:space:]' ' ' | sed 's/ /  /g' ; echo '')
if [ -n "$nsservers" ] ; then
f_Long; echo -e "NAME SERVERS" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; echo -e "\n$nsservers\n" | fmt -s -w 60; fi
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
if [ $target_type = "dnsrec" ] ; then
echo "WHOIS SUMMARY" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
grep -E "^IP:|^Origin-AS:|^Prefix:|^Net-Name:|^Country-Code:" $tempdir/addr.txt | sed 's/Net-Name:/| Net:/g' | sed 's/Prefix:/|/g' |
sed 's/Country-Code:/|/g' | sed 's/Origin-AS:/| AS/' |  tr '[:space:]' ' ' | sed 's/IP: /\n\n/g' ; echo '' ; else
grep -E "^IP:|^Origin-AS:|^Prefix:|^AS-Org-Name:|^Org-Name:|^Net-Name:|^Country:" $tempdir/addr.txt |
cat $tempdir/addr.txt  | grep -E "^IP:|^Origin-AS:|^Prefix:|^AS-Org-Name:|^Org-Name:|^Net-Name:|^City:|^Geo-City:|^Country-Code:|^Geo-Country-Code:" |
sed '/IP:/i \_____________________\n' ; fi
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
v4_ranges=$(cat $tempdir/v4_ranges | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -s -w 40)
echo -e "\n__________________________________________________________________\n"; echo -e "$v4_ranges"
if [ -n "$v6_blocks" ] ; then
echo -e "__________________________________________________________________\n"; else
echo ''; fi; else
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
if [ $domain_enum = "true" ] || [ $target_type = "web" ]; then
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
echo -e "\nAS $lp_as\n"; echo -e "$less_sp_out\n" | fmt -s -w 80 ; fi ; done; fi
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
f_Long; echo -e "\nBGP PREFIX: Invalid Argument\n"; fi
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
f_seen_origin=$(jq -r '.data.first_seen.origin' $tempdir/bgp.json)
f_seen=$(jq -r '.data.first_seen.time' $tempdir/bgp.json | sed 's/T/  /g')
if [[ ${p_ip} =~ $REGEX_IP4 ]] ; then
visibility=$(jq -r '.data.visibility.v4.ris_peers_seeing' $tempdir/bgp.json)
peers_total=$(jq -r '.data.visibility.v4.total_ris_peers' $tempdir/bgp.json); else
visibility=$(jq -r '.data.visibility.v6.ris_peers_seeing' $tempdir/bgp.json)
peers_total=$(jq -r '.data.visibility.v6.total_ris_peers' $tempdir/bgp.json); fi
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
echo "ROA: $rpki_status" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
if [ $target_type = "hop" ] || [ $target_type = "net" ]; then
echo -e "BGP:          last seen:   $l_seen - AS $l_seen_origin"; echo -e "              first seen:  $f_seen - AS $f_seen_origin"
echo -e "              visibility:  $visibility/$peers_total\n"; else
echo -e "\nBGP:          last seen:   $l_seen - AS $l_seen_origin\n"
echo -e "              visibility:  $visibility/$peers_total\n"; fi
if ! [ $rpki_status = "unknown" ] ; then
echo -e "ROAs:         $validity >  $roa_prefix >  $roa_origin  > max. /$max_length\n" ; fi
}
f_showORIGIN(){
local s="$*" ; if [ $target_type = "hop" ] ; then
echo "$s" >> $tempdir/asns; as_name=$(dig +short as$s.asn.cymru.com TXT | tr -d '"' | sed 's/^[ \t]*//;s/[ \t]*$//' | cut -d '|' -f 5 | sed 's/^ *//')
echo -e "ASN:          $s  | $as_name\n" ; else
f_AS_WHOIS "${s}" ; fi
}
f_ROUTE_CONS(){
local s="$*"; f_Long ; echo "BGP-WHOIS CONSISTENCY" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
curl -s "https://stat.ripe.net/data/prefix-routing-consistency/data.json?resource=${s}" > $tempdir/rc.json
jq -r '.data.routes[] | {Pfx: .prefix, AS: .origin, N: .asn_name, BGP: .in_bgp, WHOIS: .in_whois}' $tempdir/rc.json | tr -d '{",}' | sed 's/^ *//' |
sed '/^$/d' | tr '[:space:]' ' ' | sed 's/Pfx: /\n\n/g' | sed 's/AS:/ | AS/g' | sed 's/ N:/,/g' | sed 's/BGP:/| BGP:/g' |
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

#********************** AS INFORMATION ***********************
f_AS_WHOIS() {
local s="$*" ; dig +short as$s.asn.cymru.com TXT | tr -d '"' | sed 's/^[ \t]*//;s/[ \t]*$//' > $tempdir/whois_cy_as
reg=$(head -1 $tempdir/whois_cy_as | awk -F'|' '{print $3}' | tr -d ' ' | sed 's/ripencc/ripe/')
asnum=$(head -1 $tempdir/whois_cy_as | awk -F'|' '{print $1}' | tr -d ' ')
if [ $reg = "arin" ] ; then
whois -h whois.arin.net a $s > $tempdir/AS.txt
elif [ $reg = "lacnic" ] ; then
whois -h whois.lacnic.net AS${s} > $tempdir/AS.txt ; else
whois -h whois.$reg.net -- "--no-personal AS${s}" > $tempdir/AS.txt; fi
asnum=$(head -1 $tempdir/whois_cy_as | awk -F'|' '{print $1}' | tr -d ' ' | sed 's/ripencc/ripe/')
as_ctry=$(cut -d '|' -f 2 $tempdir/whois_cy_as | sed 's/^[ \t]*//;s/[ \t]*$//' | head -1)
if [ $reg = "lacnic" ] ; then
asname=$(cut -d '|' -f 5 $tempdir/whois_cy_as | sed 's/^[ \t]*//;s/[ \t]*$//') ; else
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
local s="$*"; f_Long; dig +short as$s.asn.cymru.com TXT | tr -d '"' | sed 's/^[ \t]*//;s/[ \t]*$//' > $tempdir/whois_cy_as
rir=$(head -1 $tempdir/whois_cy_as | awk -F'|' '{print $3}' | tr -d ' ' | sed 's/ripencc/ripe/'); echo -e "AS $s\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
curl -s "https://stat.ripe.net/data/as-overview/data.json?resource=AS${s}" > $tempdir/asov.json
rir=$(head -1 $tempdir/whois_cy_as | awk -F'|' '{print $3}' | tr -d ' ' | sed 's/ripencc/ripe/')
asname=$(cut -d '|' -f 5 $tempdir/whois_cy_as | sed 's/^[ \t]*//;s/[ \t]*$//'); announced=$(jq -r '.data.announced' $tempdir/asov.json)
if [ $rir = "arin" ] ; then
whois -h whois.arin.net a ${s} > $tempdir/AS.txt
elif [ $rir = "lacnic" ] ; then
whois -h whois.lacnic.net AS${s} > $tempdir/AS.txt; else
whois -h whois.$rir.net -- "--no-personal as${s}" > $tempdir/AS.txt; fi
if [ $rir = "lacnic" ] ; then
echo -e "AS $s  $(jq -r '.data.holder' $tempdir/asov.json)"; else
echo -e "AS $s - $asname\n"; fi
echo -e "$(cut -d '|' -f 3-4 $tempdir/whois_cy_as | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/ripencc/ripe ncc/' | tr [:lower:] [:upper:]) | announced: $announced\n"
if ! [ $rir = "lacnic" ] ; then
f_getORGNAME "$tempdir/AS.txt" | cut -d ':' -f 2- | sed 's/^ *//'; echo ''; fi
if ! [ $rir = "arin" ] && ! [ $rir = "lacnic" ]; then
grep -sEa "^address:" $tempdir/AS.txt | sed '/*\*\*\*\*/d' | cut -d ':' -f 2- | sed 's/^ *//' | tr '[:space:]' ' '; echo -e "\n"; fi
grep -sEoa "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/AS.txt | sort -u | tr '[:space:]' ' ' ; echo -e "\n"
}
f_asHEADER(){
curl -s "https://stat.ripe.net/data/as-overview/data.json?resource=AS${asnum}" > $tempdir/asov.json
echo ''; f_Long ; echo "[+]  AS $asnum  -  $(jq -r '.data.holder' $tempdir/asov.json | cut -d ' ' -f 1)  |  $as_headline" ; f_Long
}
f_listPEERS(){
local s="$*"; grep -E "^[0-9]{1}\|" ${s} | sed 's/|/      |/g' | sed 's/descr:/|/g' | sed 's/country:/|/g' > $tempdir/1
grep -E "^[0-9]{2}\|" ${s} | sed 's/|/     |/g' | sed 's/descr:/|/g' | sed 's/country:/|/g' > $tempdir/2
grep -E "^[0-9]{3}\|" ${s} | sed 's/|/    |/g' | sed 's/descr:/|/g' | sed 's/country:/|/g' > $tempdir/3
grep -E "^[0-9]{4}\|" ${s} | sed 's/|/   |/g' | sed 's/descr:/|/g' | sed 's/country:/|/g' > $tempdir/4
grep -E "^[0-9]{5}\|" ${s} | sed 's/|/  |/g' | sed 's/descr:/|/g' | sed 's/country:/|/g' > $tempdir/5
grep -E "^[0-9]{6}\|" ${s} | sed 's/|/ |/g' | sed 's/descr:/|/g' | sed 's/country:/|/g' > $tempdir/6
cat $tempdir/1 > $tempdir/peers; cat $tempdir/2 >> $tempdir/peers; cat $tempdir/3 >> $tempdir/peers
cat $tempdir/4 >> $tempdir/peers; cat $tempdir/5 >> $tempdir/peers; cat $tempdir/6 >> $tempdir/peers
}
f_PEERING(){
if ! [ $option_as = "2" ] ; then
f_asHEADER; fi
announced=$(jq -r '.data.announced' $tempdir/asov.json)
if [ $announced = "true" ] ; then
curl -s https://api.bgpview.io/asn/${asnum}/peers > $tempdir/peers.json
jq -r '.data.ipv4_peers[] | {asn: .asn, name: .name, descr: .description, country: .country_code}' $tempdir/peers.json | tr -d '{,\"}' | sed 's/^ *//' |
sed '/^$/d' | tr '[:space:]' ' ' | sed 's/asn: /\n\n/g' | sed 's/ name:/|/g' | sort -t ' ' -g | sed '/^$/d' | sed 's/ |/|/g' > $tempdir/peers_v4
echo -e "PEERS:  IPV4\n\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
f_listPEERS "$tempdir/peers_v4"; if [ -f $tempdir/peers ]; then
sed '/^$/d' $tempdir/peers | sed G; rm $tempdir/peers; else
echo -e "No results from bgpview.io\n"; fi
jq -r '.data.ipv6_peers[] | {asn: .asn, name: .name, descr: .description, country: .country_code}' $tempdir/peers.json | tr -d '{,\"}' | sed 's/^ *//' |
sed '/^$/d' | tr '[:space:]' ' ' | sed 's/asn: /\n\n/g' | sed 's/ name:/|/g' | sort -t ' ' -g | sed '/^$/d' | sed 's/ |/|/g' > $tempdir/peers_v6
f_listPEERS "$tempdir/peers_v6"; f_Long; echo -e "PEERS:  IPV6\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
if [ -f $tempdir/peers ]; then
echo ''; sed '/^$/d' $tempdir/peers | sed G; rm $tempdir/peers; else
echo -e "No results from bgpview.io\n"; fi; fi
}
f_bgpPREFIXES(){
announced=$(jq -r '.data.announced' $tempdir/asov.json)
if [ $announced = "true" ] ; then
curl -s "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS$asnum" > $tempdir/pfx.json
pfxv4=$(jq -r '.data.prefixes[] | .prefix' $tempdir/pfx.json | grep -v ':' | sort -V)
pfxv6=$(jq -r '.data.prefixes[] | .prefix' $tempdir/pfx.json | grep ':' | sort -V)
if [ -n "$pfxv4" ] ; then
echo -e "\n -- IPv4 --\n\n"; echo "$pfxv4" | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -s -w 60 | sed G; fi
if [ -n "$pfxv6" ] ; then
if [ -n "$pfxv4" ] ; then
echo ''; fi
echo -e "\n -- IPv6 --\n\n"; echo "$pfxv6" | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -s -w 60 | sed G; fi; else
echo -e "\nAS is not announced\n" ; fi
}
f_BGPviewPREFIXES(){
f_asHEADER; announced=$(jq -r '.data.announced' $tempdir/asov.json)
if [ $announced = "true" ] ; then
curl -s https://api.bgpview.io/asn/${asnum}/prefixes  > $tempdir/pfxs.json
echo -e "\nIPv6 Prefixes\n______________"
jq -r '.data.ipv6_prefixes[] | {P: .prefix, Name: .name, Loc: .country_code, Descr: .description, ROA: .roa_status}' $tempdir/pfxs.json | sed '/null/d' |
tr -d '{",}' | sed 's/^ *//' | sed '/^$/d' | tr '[:space:]' ' ' | sed '/P:/G' | sed 's/P: /\n\n/g' | sed 's/Name: /\n\n/g' | sed 's/Descr:/|/g' |
sed 's/Loc:/|/g' | sed 's/ROA:/| ROA:/g' | sed '/|/G' ; echo ''; echo -e "\nIPv4 Prefixes\n______________"
jq -r '.data.ipv4_prefixes[] | {P: .prefix, Name: .name, Loc: .country_code, Descr: .description, ROA: .roa_status}' $tempdir/pfxs.json | sed '/null/d' |
tr -d '{",}' | sed 's/^ *//' | sed '/^$/d' | tr '[:space:]' ' ' | sed '/P:/G' | sed 's/P: /\n\n/g' | sed 's/Name: /\n\n/g' | sed 's/Descr:/|/g' |
sed 's/Loc:/|/g' | sed 's/ROA:/| ROA:/g' | sed '/|/G' ; echo '' ; else
echo -e "\nAS is not announced\n" ; fi
}
f_asINFO(){
local s="$*"; echo ''; option_detail="2"; curl -s "https://stat.ripe.net/data/as-overview/data.json?resource=AS${asnum}" > $tempdir/asov.json
dig +short as$asnum.asn.cymru.com TXT | tr -d '"' | sed 's/^[ \t]*//;s/[ \t]*$//' > $tempdir/cyas
rir=$(head -1 $tempdir/cyas | awk -F'|' '{print $3}' | tr -d ' ' | sed 's/ripencc/ripe/'); export rir
announced=$(jq -r '.data.announced' $tempdir/asov.json); if [ $rir = "arin" ] ; then
whois -h whois.arin.net a $asnum > $tempdir/whois_as
elif [ $rir = "lacnic" ] ; then
whois -h whois.lacnic.net as$asnum > $tempdir/whois_as; else
whois -h whois.$rir.net -- "--no-personal as$asnum" > $tempdir/whois_as; fi
ASNumber=$(grep -E "^ASNumber:" $tempdir/whois_as | cut -d ':' -f 2- | sed 's/^ *//')
ASHandle=$(grep -E "^ASHandle:" $tempdir/whois_as | cut -d ':' -f 2- | sed 's/^ *//')
curl -s https://api.bgpview.io/asn/${asnum} > $tempdir/asn.json
curl -s "https://stat.ripe.net/data/routing-status/data.json?resource=AS${asnum}" > $tempdir/status.json
curl -s -m 5 "https://api.asrank.caida.org/v2/restful/asns/${asnum}" > $tempdir/caida.json
as_descr=$(jq -r '.data.description_full[]' $tempdir/asn.json)
traffic=$(jq -r '.data.traffic_estimation' $tempdir/asn.json | sed 's/null/no data/')
ratio=$(jq -r '.data.traffic_ratio'  $tempdir/asn.json | sed 's/null/no data/')
as_size=$(jq -r '.data.announced_space.v4.ips' $tempdir/status.json | sed -e :a -e 's/\(.*[0-9]\)\([0-9]\{3\}\)/\1,\2/;ta')
pfx_v4_num=$(jq -r '.data.announced_space.v4.prefixes' $tempdir/status.json)
pfx_v6_num=$(jq -r '.data.announced_space.v6.prefixes' $tempdir/status.json)
l_glass=$(jq -r '.data.looking_glass' $tempdir/asn.json)
as_org=$(grep -s -E -a "^OrgName:|^org-name:|^owner" $tempdir/whois_as | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
org_id=$(grep -s -E -m 1 "^OrgId:|^organisation:|^owner-c:" $tempdir/whois_as | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
abuse_c=$(jq -r '.data.abuse_contacts[0]' $tempdir/asn.json | sed '/null/d')
if [ -z "$abuse_c" ] ; then
abuse_c=$(grep -s -E -o -m 1 "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/whois_as); fi
echo ''; f_Long ; echo "[+]  AS $asnum  $(jq -r '.data.holder' $tempdir/asov.json)  |  $(date)"; f_Long
echo "[@]: $abuse_c" ; echo -e "____\n"
if [ $rir = "arin" ] && [ -n "$ASNumber" ] ; then
echo -e "\nASNumber:       $ASNumber"; echo -e "\nName:           $(cut -d '|' -f 5 $tempdir/cyas | sed 's/^ *//')"
echo -e "ASHandle:       $ASHandle"; else
echo -e "\nName:           $(cut -d '|' -f 5 $tempdir/cyas | sed 's/^ *//')"; fi
echo -e "\nOrg:            $as_org  ($org_id)"; echo -e "\n\nAnnounced:      $announced"
echo -e "Allocated:      $(cut -d '|' -f 4 $tempdir/cyas | sed 's/^ *//')|$(cut -d '|' -f 2,3 $tempdir/cyas)\n"
echo -e "LookingGlass:   $l_glass"; echo -e "Website:        $(jq -r '.data.website'  $tempdir/asn.json)\n"
owner_addr=$(jq -r '.data.owner_address[]' $tempdir/asn.json)
if [ -n = "$owner_addr" ] ; then
echo -e "$owner_addr"
if [ $rir = "lacnic" ]; then
echo ''; jq -r '.data.email_contacts[]' $tempdir/asn.json; fi; else
if [ $rir = "arin" ]; then
f_ARIN_ORG "$tempdir/whois_as"; fi ; fi
if ! [ $rir = "lacnic" ] && ! [ $rir = "arin" ]; then
whois -h whois.$rir.net -- "-B $org_id" > $tempdir/as_org; f_POC "$tempdir/as_org"; fi
if [ $announced = "true" ] ; then
echo ''; curl -s -m 7 https://api.bgpview.io/asn/${asnum}/ixs > $tempdir/asix.json
curl -s -m 7 "https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS${asnum}" > $tempdir/nb.json
curl -s -m 7 "https://stat.ripe.net/data/as-routing-consistency/data.json?resource=as${asnum}" > $tempdir/ascons.json
jq -r '.data.neighbours[] | {AS: .asn, T: .type}' $tempdir/nb.json | tr -d '{",}' | sed 's/^ *//' | sed '/^$/d' | sed 's/T:/|/g' |
tr '[:space:]' ' ' | sed 's/AS: /\n/g' > $tempdir/nb; nb_left=$(grep 'left' $tempdir/nb | awk '{print $1}' | sort -g)
nb_right=$(grep 'right' $tempdir/nb | awk '{print $1}' | sort -g); nb_uncertain=$(grep 'uncertain' $tempdir/nb | awk '{print $1}' | sort -g)
jq -r '.data.prefixes[] | {Pfx: .prefix, BGP: .in_bgp, WHOIS: .in_whois}' $tempdir/ascons.json | tr -d '{,"}' | sed 's/^ *//' |
sed '/^$/d' | tr '[:space:]' ' ' | sed 's/Pfx: /\n\n/g' | sed 's/WHOIS:/ | WHOIS:/g' | sed 's/BGP:/ | BGP:/g' |
sed 's/^[ \t]*//;s/[ \t]*$//' > $tempdir/ascons
v4_ok=$(grep -w 'BGP: true' $tempdir/ascons | grep -w 'WHOIS: true' | grep -v 'false' | cut -s -d '|' -f 1 | tr -d ' ' | grep -v ':')
v6_ok=$(grep -w 'BGP: true' $tempdir/ascons | grep -w 'WHOIS: true' | grep -v 'false' | cut -s -d '|' -f 1 | tr -d ' ' | grep ':')
v4_okCOUNT=$(echo "$v4_ok" | wc -w); v6_okCOUNT=$(echo "$v6_ok" | wc -w);
v4_whois_false=$(grep -w 'WHOIS: false' $tempdir/ascons | cut -s -d '|' -f 1 | tr -d ' ' | grep -v ':')
v4_whois_falseCOUNT=$(echo "$v4_whois_false" | wc -w)
v4_bgp_false=$(grep -w 'BGP: false' $tempdir/ascons | cut -s -d '|' -f 1 | tr -d ' ' | grep -v ':'); v4_bgp_falseCOUNT=$(echo "$v4_bgp_false" | wc -w)
v6_whois_false=$(grep -w 'WHOIS: false' $tempdir/ascons | cut -s -d '|' -f 1 | tr -d ' ' | grep ':'); v6_whois_falseCOUNT=$(echo "$v6_whois_false" | wc -w)
v6_bgp_false=$(grep -w 'BGP: false' $tempdir/ascons | cut -s -d '|' -f 1 | tr -d ' ' | grep ':'); v6_bgp_falseCOUNT=$(echo "$v6_bgp_false" | wc -w)
im_ok=$(jq -r '.data.imports[] | {Peer: .peer, BGP: .in_bgp, WHOIS: .in_whois}' $tempdir/ascons.json | tr -d '{",}'  | sed 's/^ *//' | sed '/^$/d' |
sed 's/BGP:/| BGP:/g' | sed 's/WHOIS:/| WHOIS:/g' | tr '[:space:]' ' ' | sed 's/Peer: /\n/g' | grep -v 'false' | awk '{print $1}' | sort -g)
ex_ok=$(jq -r '.data.exports[] | {Peer: .peer, BGP: .in_bgp, WHOIS: .in_whois}' $tempdir/ascons.json | tr -d '{",}'  | sed 's/^ *//' | sed '/^$/d' |
sed 's/BGP:/| BGP:/g' | sed 's/WHOIS:/| WHOIS:/g' | tr '[:space:]' ' ' | sed 's/Peer: /\n/g' | grep -v 'false' | awk '{print $1}' | sort -g)
im_b_true=$(jq -r '.data.imports[] | {Peer: .peer, BGP: .in_bgp}' $tempdir/ascons.json | tr -d '{",}' | sed 's/^ *//' | sed '/^$/d' | sed 's/BGP/| BGP/g' |
tr '[:space:]' ' ' | sed 's/Peer: /\n/g' | grep 'true' | awk '{print $1}' | sort -g)
im_b_false=$(jq -r '.data.imports[] | {Peer: .peer, BGP: .in_bgp}' $tempdir/ascons.json | tr -d '{",}' | sed 's/^ *//' | sed '/^$/d' | sed 's/BGP/| BGP/g' |
tr '[:space:]' ' ' | sed 's/Peer: /\n/g' | grep 'false' | awk '{print $1}' | sort -g)
im_w_true=$(jq -r '.data.imports[] | {Peer: .peer, WHOIS: .in_whois}' $tempdir/ascons.json | tr -d '{",}' | sed 's/^ *//' | sed '/^$/d' |
sed 's/WHOIS/| WHOIS/g' | tr '[:space:]' ' ' | sed 's/Peer: /\n/g' | grep 'true' | awk '{print $1}' | sort -g)
im_w_false=$(jq -r '.data.imports[] | {Peer: .peer, WHOIS: .in_whois}' $tempdir/ascons.json | tr -d '{",}' | sed 's/^ *//' | sed '/^$/d' |
sed 's/WHOIS/| WHOIS/g' | tr '[:space:]' ' ' | sed 's/Peer: /\n/g' | grep 'false' | awk '{print $1}' | sort -g)
ex_b_true=$(jq -r '.data.exports[] | {Peer: .peer, BGP: .in_bgp}' $tempdir/ascons.json | tr -d '{",}' | sed 's/^ *//' | sed '/^$/d' | sed 's/BGP/| BGP/g' |
tr '[:space:]' ' ' | sed 's/Peer: /\n/g' | grep 'true' | awk '{print $1}' | sort -g)
ex_b_false=$(jq -r '.data.exports[] | {Peer: .peer, BGP: .in_bgp}' $tempdir/ascons.json | tr -d '{",}' | sed 's/^ *//' | sed '/^$/d' | sed 's/BGP/| BGP/g' |
tr '[:space:]' ' ' | sed 's/Peer: /\n/g' | grep 'false' | awk '{print $1}' | sort -g)
ex_w_true=$(jq -r '.data.exports[] | {Peer: .peer, WHOIS: .in_whois}' $tempdir/ascons.json | tr -d '{",}' | sed 's/^ *//' | sed '/^$/d' |
sed 's/WHOIS/| WHOIS/g' | tr '[:space:]' ' ' | sed 's/Peer: /\n/g' | grep 'true' | awk '{print $1}' | sort -g)
ex_w_false=$(jq -r '.data.exports[] | {Peer: .peer, WHOIS: .in_whois}' $tempdir/ascons.json | tr -d '{",}' | sed 's/^ *//' | sed '/^$/d' |
sed 's/WHOIS/| WHOIS/g' | tr '[:space:]' ' ' | sed 's/Peer: /\n/g' | grep 'false' | awk '{print $1}' | sort -g)
imokCount=$(echo "$im_ok" | wc -w); exokCount=$(echo "$ex_ok" | wc -w); imb_falseCount=$(echo "$im_b_false" | wc -w)
imb_trueCount=$(echo "$im_b_true" | wc -w); imw_trueCount=$(echo "$im_w_true" | wc -w); imw_falseCount=$(echo "$im_w_false" | wc -w)
exb_trueCount=$(echo "$ex_b_true" | wc -w); exb_falseCount=$(echo "$ex_b_false" | wc -w); exw_trueCount=$(echo "$ex_w_true" | wc -w)
exw_falseCount=$(echo "$ex_w_false" | wc -w); n_observed=$(jq -r '.data.observed_neighbours' $tempdir/status.json)
n_unique=$(jq -r '.data.neighbour_counts.unique' $tempdir/nb.json); n_left=$(jq -r '.data.neighbour_counts.left' $tempdir/nb.json)
n_right=$(jq -r '.data.neighbour_counts.right' $tempdir/nb.json); n_isp=$(jq -r '.data.asn.asnDegree.provider' $tempdir/caida.json)
f_Long; echo "STATISTICS" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; echo -e "Data Traffic\n____________\n"
echo "Ratio:          $ratio"; echo "Volume:         $traffic"; echo -e "\n\nNeighbours\n__________\n"
echo -e "Observed: $n_observed | Unique: $n_unique | Left: $n_left | Right: $n_right | Providers: $n_isp"
echo -e "\n\nBGP Prefixes\n_____________\n"
echo -e "IPv4: $pfx_v4_num ($as_size IPs) | IPv6: $pfx_v6_num\n"
f_Long ; echo -e "IX PRESENCE" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
asix=$(jq -r '.data[] | {IXid: .ix_id, Na: .name, Ct: .country_code, Cy: .city, Speed: .speed, IPv4: .ipv4_address, IPv6: .ipv6_address}' $tempdir/asix.json |
tr -d '{",}' | sed 's/^ *//' | sed '/^$/d' | tr '[:space:]' ' ' | sed 's/IXid:/\nID:/g' | sed 's/Na: /\n\n/g' | sed 's/Ct:/|/g' | sed 's/Cy:/|/g' |
sed 's/Speed:/| Speed:/g' | sed 's/IPv4: /\n\nIP: /g' | sed '/IP:/G' |  sed 's/IPv6://g' | sed '/IP:/G')
if [ -n "$asix" ] ; then
echo -e "$asix\n" ; else
echo -e "Unknown / NA\n" ; fi
echo '' ; f_Long; echo -e "BGP PREFIXES" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; f_bgpPREFIXES
echo ''; f_Long ; echo -e "NEIGHBOURS\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' ; echo -e "LEFT\n"
echo "$nb_left" | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -s -w 50 | sed G
if [ -n "$nb_right" ]; then
echo -e "\n\nRIGHT\n"; echo "$nb_right" | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -s -w 50 | sed G; fi
if [ -n "$nb_uncertain" ]; then
echo -e "\n\nUNCERTAIN\n"; echo "$nb_uncertain" | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -s -w 50 | sed G; fi
jq -r '.data.neighbours[] | {ASN: .asn, IPv4: .v4_peers, IPv6: .v6_peers}' $tempdir/nb.json | tr -d '{",}' | sed 's/^ *//' | sed '/^$/d' |
sed 's/IPv4:/| Peers:  IPv4:/g' | tr '[:space:]' ' ' | sed 's/ASN: /\n\n/g' | sed 's/IPv6:/\/ IPv6:/g' |
sed 's/^ *//' | sort -t '|' -k 1 -ug > $tempdir/neighbours
curl -s https://api.bgpview.io/asn/${asnum}/peers > $tempdir/peers.json
jq -r '.data.ipv4_peers[] | {asn: .asn, name: .name, descr: .description, country: .country_code}' $tempdir/peers.json | tr -d '{,\"}' | sed 's/^ *//' |
sed '/^$/d' | tr '[:space:]' ' ' | sed 's/asn: /\n\n/g' | sed 's/ name:/|/g' | sort -t ' ' -g | sed '/^$/d' | sed 's/ |/|/g' > $tempdir/peers_v4
jq -r '.data.ipv6_peers[] | {asn: .asn, name: .name, descr: .description, country: .country_code}' $tempdir/peers.json | tr -d '{,\"}' | sed 's/^ *//' |
sed '/^$/d' | tr '[:space:]' ' ' | sed 's/asn: /\n\n/g' | sed 's/ name:/|/g' | sort -t ' ' -g | sed '/^$/d' | sed 's/ |/|/g' > $tempdir/peers_v6
f_listPEERS "$tempdir/peers_v4"
if [ -f $tempdir/peers ]; then
echo ''; f_Long; echo -e "NEIGHBOURS  (IPV4)\n\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
peers=$(awk '{print $1}' $tempdir/peers)
for p in $peers; do
peer_summary=$(grep -Esa -m 1 "^${p}" $tempdir/peers | sed 's/^[ \t]*//;s/[ \t]*$//')
peer_power=$(grep -Esa -m 1 "^${p}" $tempdir/neighbours | cut -d '|' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
if [ -n "$peer_power" ] && [ -n "$peer_summary" ]; then
echo -e "\n$peer_summary | $peer_power"
fi; done; rm $tempdir/peers; fi; echo ''
f_listPEERS "$tempdir/peers_v6"
if [ -f $tempdir/peers ]; then
echo ''; f_Long; echo -e "NEIGHBOURS  (IPV6)\n\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
peers=$(awk '{print $1}' $tempdir/peers)
for p in $peers; do
peer_summary=$(grep -Esa -m 1 "^${p}" $tempdir/peers | sed 's/^[ \t]*//;s/[ \t]*$//')
peer_power=$(grep -Esa -m 1 "^${p}" $tempdir/neighbours | cut -d '|' -f 2- | sed 's/^ *//' | sed 's/^[ \t]*//;s/[ \t]*$//')
if [ -n "$peer_power" ] && [ -n "$peer_summary" ]; then
echo -e "\n$peer_summary | $peer_power"; fi; done ; rm $tempdir/peers; fi; echo ''
echo ''; if [ $rir = "ripe" ]; then
curl -s "https://stat.ripe.net/data/reverse-dns-consistency/data.json?resource=AS${asnum}" > $tempdir/dnscons.json
missing_ipv4=$(jq -r '.data.prefixes.ipv4' $tempdir/dnscons.json | tr -d '}],"[{' | sed 's/^ *//' | sed '/^$/d' | sed -n '/complete: false/{g;1!p;};h' |
rev | cut -c 3- | rev); missing_ipv4COUNT=$(echo "$missing_ipv4" | wc -w)
missing_ipv6=$(jq -r '.data.prefixes.ipv6' $tempdir/dnscons.json | tr -d '}],"[{' | sed 's/^ *//' | sed '/^$/d' | sed -n '/complete: false/{g;1!p;};h' |
rev | cut -c 3- | rev); missing_ipv6COUNT=$(echo "$missing_ipv6" | wc -w); fi
dnscons4_false=$(jq -r '.data.prefixes.ipv4[] | .domains[] | {Dom: .domain, Pfx: .prefix, Found: .found}' $tempdir/dnscons.json | tr -d '{\",}' |
sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' | tr '[:space:]' ' ' | sed 's/Dom: /\n/g' | sed 's/ Pfx:/,  /g'  | sed 's/Found:/|/g' | grep 'false' |
cut -d '|' -f -1; echo '')
dnscons6_false=$(jq -r '.data.prefixes.ipv6[] | .domains[] | {Dom: .domain, Pfx: .prefix, Found: .found}' $tempdir/dnscons.json | tr -d '{\",}' |
sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' | tr '[:space:]' ' ' | sed 's/Dom: /\n/g' | sed 's/ Pfx:/,  /g'  | sed 's/Found:/|/g' | grep 'false' |
cut -d '|' -f -1; echo '')
f_Long; echo "[+]  AS $asnum  |  WHOIS <> ADDRESS SPACE / BGP  CONSISTENCY"; f_Long
echo "OVERVIEW" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
echo -e "\nImports\n_______\n"
echo -e "Whois - true: $imw_trueCount; false: $imw_falseCount | BGP - true: $imb_trueCount; false: $imb_falseCount | OK: $imokCount"
echo -e "\n\nExports\n_______\n"
echo -e "Whois - true: $exw_trueCount; false: $exw_falseCount | BGP - true: $exb_trueCount; false: $exb_falseCount | OK: $exokCount"
echo -e "\n\nIPv4 Prefixes\n_____________\n"
echo -e "Announced & found in Whois: $v4_okCOUNT | Not announced: $v4_bgp_falseCOUNT | Not found in Whois: $v4_whois_falseCOUNT"
echo -e "\n\nIPv6 Prefixes\n_____________\n"
echo -e "Announced & found in Whois: $v6_okCOUNT | Not announced: $v6_bgp_falseCOUNT | Not found in Whois: $v6_whois_falseCOUNT\n"
if [ $rir = "ripe" ]; then
echo -e "\nReverse DNS Zones\n_________________\n"
echo -e "Incomplete whois entries found for  $missing_ipv4COUNT IPv4-  and  $missing_ipv6COUNT IPv6 resources\n"; fi
echo ''; f_Long; echo "IMPORTS" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
echo -e "\nIn WHOIS & in BGP\n_________________\n\n"
if [ -n "$im_ok" ]; then
echo "$im_ok" | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -s -w 50 | sed G; else
echo -e "NA.\n"; fi
if [ -n "$im_w_false" ]; then
echo -e "\nNOT in WHOIS\n____________\n"; echo "$im_w_false" | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -s -w 50 | sed G; fi
if [ -n "$im_b_false" ]; then
echo -e "\n\nNOT seen in BGP\n_______________\n\n"; echo "$im_b_false" | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -s -w 50 | sed G; fi
echo ''; f_Long; echo "EXPORTS" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; echo -e "\nIn WHOIS & in BGP\n_________________\n\n"
if [ -n "$ex_ok" ]; then
echo "$ex_ok" | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -s -w 50 | sed G; else
echo -e "NA.\n"; fi
if [ -n "$ex_w_false" ]; then
echo -e "\nNOT in WHOIS\n____________\n"; echo "$ex_w_false" | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -s -w 50 | sed G; fi
if [ -n "$ex_b_false" ]; then
echo -e "\n\nNOT seen in BGP\n_______________\n\n"; echo "$ex_b_false" | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' |
fmt -s -w 50 | sed G; fi
if [ -n "$v4_whois_false" ] || [ -n "$v6_whois_false" ]; then
echo '' ; f_Long; echo -e "PREFIXES: NOT FOUND IN WHOIS" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
if [ -n "$v4_whois_false" ]; then
echo -e "\n -- IPv4 --\n"; echo -e "$v4_whois_false" | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -s -w 60 | sed G; fi
if [ -n "$v6_whois_false" ]; then
echo -e "\n -- IPv6 --\n"; echo -e "$v6_whois_false" | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -s -w 60 | sed G; fi; fi
if [ -n "$v4_bgp_false" ] || [ -n "$v6_bgp_false" ]; then
f_Long; echo -e "PREFIXES: NOT ANNOUNCED" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
if [ -n "$v4_bgp_false" ]; then
echo -e "\n -- IPv4 --\n\n"; echo -e "$v4_bgp_false" | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -s -w 60 | sed G; fi
if [ -n "$v6_bgp_false" ]; then
echo -e "\n -- IPv6 --\n\n"; echo -e "$v6_bgp_false" | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -s -w 60 | sed G; fi; fi
if [ $rir = "ripe" ]; then
if [ -n "$missing_ipv4" ] || [ -n "$missing_ipv6" ]; then
echo ''; f_Long; echo -e "REVERSE DNS ZONES" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
echo -e "\n\nInconsistent whois entries for reverse DNS zones have been found for the following prefixes:\n"
if [ -n "$missing_ipv4" ]; then
echo "$missing_ipv4" | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -s -w 60 | sed G
if [ -n "$missing_ipv6" ]; then
echo ''; fi; fi
if [ -n "$missing_ipv6" ]; then
echo "$missing_ipv6" | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -s -w 60 | sed G; fi; fi; fi; fi
}
f_CLEANUP_FILES(){
[[ -f $tempdir/headers ]] && rm $tempdir/headers; [[ -f $tempdir/h2 ]] && rm $tempdir/h2; [[ -f $tempdir/h3 ]] && rm $tempdir/h3
[[ -f $tempdir/sec_headers_alternate ]] && rm $tempdir/sec_headers_alternate; [[ -f $tempdir/net.json ]] && rm $tempdir/net.json
[[ -f $tempdir/app_headers_alternate ]] && rm $tempdir/app_headers_alternate; [[ -f $tempdir/geo.json  ]] && rm $tempdir/geo.json
[[ -f $tempdir/addresses ]] && rm $tempdir/addresses; [[ -f $tempdir/domain_status ]] && rm $tempdir/domain_status
[[ -f $tempdir/linkdump.txt ]] && rm $tempdir/linkdump.txt; [[ -f $tempdir/linkdump ]] && rm $tempdir/linkdump
[[ -f $tempdir/mime_types ]] && rm $tempdir/mime_types; [[ -f $tempdir/ograph ]] && rm $tempdir/ograph; [[ -f $tempdir/nmap.txt ]] && rm $tempdir/nmap.txt
[[ -f $tempdir/webtech_n_style ]] && rm $tempdir/webtech_n_style; [[ -f $tempdir/ww.txt ]] && rm $tempdir/ww.txt
[[ -f $tempdir/web_hashes ]] && rm $tempdir/web_hashes; [[ -f $tempdir/cdn_detect ]] && rm $tempdir/cdn_detect
[[ -f $tempdir/whois ]] && rm $tempdir/whois; [[ -f $tempdir/ac ]] && rm $tempdir/ac; [[ -f $tempdir/provider_domains ]] && rm $tempdir/provider_domains
[[ -f $tempdir/whois2 ]] && rm $tempdir/whois2; [[ -f $tempdir/whois.txt ]] && rm $tempdir/whois.txt
[[ -f $tempdir/rpki.json ]] && rm $tempdir/rpki.json; [[ -f $tempdir/pov.json ]] && rm $tempdir/pov.json
[[ -f $tempdir/pov2.json ]] && rm $tempdir/pov2.json; [[ -f $tempdir/as_sum ]] && rm $tempdir/as_sum
[[ -f $tempdir/bgp.json ]] && rm $tempdir/bgp.json; [[ -f $tempdir/netgeo.json  ]] && rm $tempdir/netgeo.json
[[ -f $tempdir/mx4.list ]] && rm $tempdir/mx4.list; [[ -f $tempdir/mx6.list ]] && rm $tempdir/mx6.list
[[ -f $tempdir/ns4.list ]] && rm $tempdir/ns4.list; [[ -f $tempdir/ns6.list ]] && rm $tempdir/ns6.list
[[ -f $tempdir/subs2 ]] && rm $tempdir/subs2; [[ -f $tempdir/prefix_status ]] && rm $tempdir/prefix_status
[[ -f $tempdir/ports ]] && rm $tempdir/ports; [[ -f $tempdir/nse ]] && rm $tempdir/nse; [[ -f $tempdir/script_args ]] && rm $tempdir/script_args
[[ -f $tempdir/prefixes.list ]] && rm $tempdir/prefixes.list; [[ -f $tempdir/provider_domains ]] && rm $tempdir/provider_domains
[[ -f $tempdir/fcrdns ]] && rm $tempdir/fcrdns
}
f_CLEANUP_FILES_NET(){
[[ -f $tempdir/whois ]] && rm $tempdir/whois; [[ -f $tempdir/whois2 ]] && rm $tempdir/whois2; [[ -f $tempdir/whois.txt ]] && rm $tempdir/whois.txt
[[ -f $tempdir/pov2.json ]] && rm $tempdir/pov2.json; [[ -f $tempdir/netgeo.json  ]] && rm $tempdir/netgeo.json; [[ -f $tempdir/ac ]] && rm $tempdir/ac
[[ -f $tempdir/bgp.json ]] && rm $tempdir/bgp.json; [[ -f $tempdir/rpki.json ]] && rm $tempdir/rpki.json
[[ -f $tempdir/prefix_status ]] && rm $tempdir/prefix_status
}

#*****************  SUBMENUS *****************
f_optionsAS(){
echo -e "\n   ${B}Options > AUTONOMOUS SYSTEMS / BGP / INTERNET EXCHANGES ${D}\n"
echo -e "   ${B}[1]${D}  AS & BGP Prefixes ${bold}Summary${D}"
echo -e "   ${B}[2]${D}  AS ${bold}Full Report${D} (AS Details, Whois/BGP <> Address Space Consistency"
echo -e "   ${B}[3]${D}  Announced Prefixes"
echo -e "   ${B}[4]${D}  AS Peers"
echo -e "   ${B}[5]${D}  Prefix BGP Status"
echo -e "   ${B}[6]${D}  IX Info (Input: IX-ID)"
echo -e "\n   ${B}[b]${D}  Back to the Global ${G2}Options Menu${D}"
}
f_optionsDNS(){
echo -e "\n   ${B}Options > DNS ${D}\n"
echo -e "   ${B}[1]${D}  Domain DNS Records ${bold}Summary${D}"
echo -e "   ${B}[2]${D}  Domain DNS Records ${bold}Details${D}"
echo -e "   ${B}[3]${D}  Shared Name Servers"
if [ $option_connect = "0" ] ; then
echo -e "   ${B}[4]${D}  Zone Transfer" ; else
echo -e "   ${B}[4]${D}  Zone Transfer, Zone Walk" ; fi
echo -e "   ${B}[5]${D}  MX Records/Mail Servers ${bold}SSL${D}"
echo -e "   ${B}[6]${D}  dig Batch Mode (Mass DNS Lookup)"
echo -e "\n   ${B}[b]${D}  Back to the Global ${G2}Options Menu${D}"
}
f_optionsHOSTS(){
echo -e "\n   ${B}Options > HOST INFORMATION\n"
echo -e "   ${B}[1]${D}  Host-/ IP Address ${bold}Summary${D}"
echo -e "   ${B}[2]${D}  ${bold}Customize${D} Options"
echo -e "   ${B}[3]${D}  Virtual Hosts  ${B}(IPv4)"
echo -e "\n   ${B}[b]${D}  Back to the Global ${G2}Options Menu${D}"
}
f_optionsLAN(){
echo -e "\n   ${B}Options > LOCAL NETWORK OPTIONS (TOOLS: NMAP, THC ATK-6) ${D} $denied\n"
echo -e "   ${B}[1]${D}  LAN Discovery (DHCP, Routing, Hosts & Services)  ${B}(IPv4, partial IPv6 support)"
echo -e "   ${B}[2]${D}  Send ARP Broadcast (Host Discovery)              ${B}(IPv4)"
echo -e "   ${B}[3]${D}  Send DHCP Discover Broadcast                     ${B}(IPv4)"
echo -e "   ${B}[4]${D}  Get Router WAN IP via NAT Port Mapping           ${B}(IPv4)"
echo -e "   ${B}[5]${D}  Network & SCADA Services & Vulnerability Scan    ${B}(IPv4)"
echo -e "   ${B}[6]${D}  IPv6 Router- & DHCP6 Summary                    ${G2}(IPv6)"
echo -e "\n   ${B}[b]${D}  Back to the Global ${G2}Options Menu${D}"
}
f_optionsMTU() {
echo -e "\n  ${B}Options > MTU DISCOVERY ${D}$denied \n"
echo -e "  ${B}[m1]${G2}  NMAP     ${D}   No Frills MTU Discovery"
echo -e "  ${B}[m2]${G2}  Tracepath${D}   Traceroute & MTU Discovery (ICMP, non-root)"
echo -e "  ${B}[m3]${G2}  atk-trace6${D}  ICMPv6 Traceroute, MTUs- & Tunnel-Discovery"
echo -e "\n   ${B}[b]${D}   Back to the Global Options ${G2}Menu${D}"
}
f_optionsNET(){
echo -e "\n   ${B}Options > NETWORKS\n\n"
echo -e "   ${B}[1]${D}  Network ${bold}Summary${D}"
echo -e "   ${B}[2]${D}  ${bold}Customize${D} Options"
echo -e "   ${B}[3]${D}  Network ${bold}Report${D} $denied"
echo -e "   ${B}[4]${D}  Prefix Address Space    (Subnets)\n"
echo -e "   ${B}[5]${D}  Reverse DNS Lookup      ${B}(IPv4)"
echo -e "   ${B}[6]${D}  Reverse DNS Lookup      ${B}(IPv6, max-size: /48))"
echo -e "   ${B}[7]${D}  Virtual Hosts (Rev.IP)  ${B}(IPv4)${D}"
echo -e "   ${B}[8]${D}  Ping Sweep              ${B}(IPv4)${D} $denied"
echo -e "   ${B}[9]${D}  Service Banners         ${B}(IPv4)${D}"
echo -e "\n   ${B}[b]${D}  Back to the Global ${G2}Options Menu${D}"
}
f_options_P(){
echo -e "\n  ${B}Options > PING PROBES & NMAP PORT SCANS${D}\n\n"
echo -e "  ${B}[p1]${G2}   NPING${D}  Ping Probes  (ICMP, TCP & UDP)"
echo -e "  ${B}[p2]${G2}   API${D}    Test Ping    ${B}IPv4${D}  (hackertarget.com API, API key required)"
echo -e "  ${B}[p3]${G2}   NMAP${D}   Port-, OS/Version- & Vulnerability Scans $denied"
echo -e "  ${B}[p4]${G2}   API${D}    Port Scan    ${B}IPv4${D}  (hackertarget.com API)"
echo -e "  ${B}[p5]${G2}   NMAP${D}   Firewalk & Basic Firewall Evasion Options $denied"
echo -e "\n   ${B}[b]${D}   Back to the Global Options ${G2}Menu${D}"
}
f_options_T() {
echo -e "\n  ${B}Options > TRACEROUTE${D}\n"
echo -e "  ${B}[t1]${G2}   Tracepath${D}          traceroute & MTUs, non-root  $denied"
echo -e "  ${B}[t2]${G2}   MTR${D}                RT-Times, Packet Loss, Jitter; TCP,UDP,ICMP  $denied"
echo -e "  ${B}[t3]${G2}   API${D}                MTR via hackertarget.com  ${B}IPv4"
echo -e "  ${B}[t4]${G2}   Nmap${D}               TCP Traceroute & MaxMind Geolocation Data  $denied"
echo -e "  ${B}[t5]${G2}   Dublin Traceroute${D}  NAT-aware, Multipath Tracerouting  $denied"
echo -e "  ${B}[t6]${G2}   atk-trace6${D}         ICMPv6 Traceroute MTU- & Tunnel-Discovery  $denied"
echo -e "\n   ${B}[b]${D}   Back to the Global Options ${G2}Menu${D}\n"
f_Long; echo -e "\n${B}Additional Options > ${G2}ROA Validation, Geolocation & whois Summary for each Hop${D}\n"; f_Long
}
f_optionsWHOIS(){
echo -e "\n   ${B}Options > WHOIS ${D}\n"
echo -e "   ${B}[1]${G2} RIPE|AFRINIC|APNIC ${B}>${D}  Organisations, Networks & PoCs (inverse & regular searches)"
echo -e "   ${B}[2]${G2} ARIN               ${B}>${D}  Organisations, Networks & PoCs"
echo -e "   ${B}[3]${G2} pwhois.org         ${B}>${D}  Org & NetBlock Searches"
echo -e "   ${B}[4]${G2} pwhois.org         ${B}>${D}  Whois Bulk Lookup (file input)"
echo -e "\n   ${B}[b]${D} Back to the Global ${G2}Options Menu${D}"
}
f_optionsWWW(){
echo -e "\n   ${B}Options > WEB SERVERS $denied\n"
echo -e "   ${B}[1]${D}  Server ${bold}Health Check${D}"
echo -e "   ${B}[2]${D}  Server Health- & Vulnerability Check"
echo -e "   ${B}[3]${D}  ${bold}Customize${D} Test Options"
echo -e "   ${B}[4]${D}  Website Overview"
echo -e "   ${B}[5]${D}  Dump HTTP Headers"
echo -e "   ${B}[6]${D}  Dump SSL Certificate Files & SSL Quick- / Bulk Info"
echo -e "\n   ${B}[b]${D}  Back to the Global ${G2}Options Menu${D}"
}

#***************************** main program loop *****************************
while true
do
echo -e -n "\n    ${B}?${D}    " ; read choice
if [ $option_connect = "0" ] ; then
denied=" (target-connect-mode only)" ; else
denied='' ; fi
case $choice in
o|b|options) echo ''; f_Long; f_Menu ;;
cc|clear)
clear ; f_Menu
;;
#************** TOGGLE CONNECT/NON-CONNECT-MODES *******************
c|con|connect) echo '' ; f_Long; f_targetCONNECT; echo '' ; f_Menu
;;
h|help|all|about)
#************** ABOUT / HELP  *******************
echo -e "${B}" ; f_Long
echo -e "\n ---------------" ; echo -e "  drwho.sh" ; echo -e " ---------------\n"
echo -e "https://github.com/ThomasPWy/drwho.sh,  Author: Thomas Wy,  Version: 2.2 (Feb 2022)"; f_Long ; echo -e "${D}"
echo -e "${G2}DEPENDENCIES ${D}"
echo -e "\n${B}Dependencies (essential):${D}\n"
echo "curl, dnsutils (installs dig & host), jq, ipcalc, lynx, nmap, openssl, whois"
echo -e "\n\n${B}Dependencies (recommended):${D}\n"
echo "dublin-traceroute, lbd, mtr, sslscan, testssl, thc-ipv6, tracepath ('iputils-tracepath' in Debian/Ubuntu, 'tracepath' in Termux), wfuzz, whatweb"
echo -e "${B}" ; f_Long
echo -e "${G2}CUSTOMIZATIONS ${D}\n"
echo -e "\n${B}API KEYS ${D}\n"
echo -e "Please enter your API-Keys in the designated fields right at the top (Lines 2+) of the drwho.sh-File.\n"
echo -e "An API key is required for usage of Project Honeypot's API. For more information visit: https://www.projecthoneypot.org/"
echo -e "\nAn API key for hackertarget's IP API is highly recommended (and required for the nping API) Without API key, there's a limit of 50 API calls/day."
echo -e "\nFor more information visit: https://hackertarget.com/"
echo -e "\n\n${B}EXECUTABLES ${D}\n"
echo -e "\nCustom paths to executables of dependencies can be set below the API-key field."
echo -e "${B}" ; f_Long
echo -e "  ${G2}Menu Header${D}\n\n"
echo "Directory      >  not saving results"
echo -e "\n\nTargetConnect  >  ${GREEN}true${D}"
echo -e "\n\nThe 'Directory  >' - field shows the location, any script output is written to."
echo -e "\nTo save script output, chose option s) and enter directory name and path."
echo -e "Nmap output will also be saved in all supported formats."
echo -e "\n\nThe 'TargetConnect  >' - field indicates if packets are send from your IP-address to any target systems (true)."
echo -e "If set to false, only third party resources are queried."
echo -e "\nTo toggle {B}TARGET - CONNECT ${D} or ${B} NON-CONNECT MODES{D}. chose option c)."
echo -e "${B}" ; f_Long; echo -e "  ${G2}Target Categories\n\n"
echo -e "${B}    a)   ${D}Abuse Contact Finder"; echo -e "${B}   as)   ${D}ASNs, BGP, IX"
echo -e "${B}   bl)   ${D}Blocklists"; echo -e "${B}    d)   ${D}Domain Recon"
echo -e "${B}  dns)   ${D}DNS, MX, NS"; echo -e "${B}    g)   ${D}Rev. Google Analytics Search"
echo -e "${B}    i)   ${D}N. Interfaces, Public IP"; echo -e "${B}   ip)   ${D}IP Addresses / Hostnames"
echo -e "${B}    l)   ${D}LAN"; echo -e "${B}    m)   ${D}MTU"
echo -e "${B}    n)   ${D}Networks & Prefixes"; echo -e "${B}    p)   ${D}Ping Probes, Port Scans, Firewalk"
echo -e "${B}    t)   ${D}Traceroute Options"; echo -e "${B}    w)   ${D}Whois (Advanced & Bulk Lookup Options)"
echo -e "${B}  www)   ${D}Web Servers"
echo -e "\n\n   ${B}Options > AUTONOMOUS SYSTEMS / BGP / INTERNET EXCHANGES ${D}\n"
echo -e "   ${B}[1]${D}  AS & BGP Prefixes ${bold}Summary${D}"
echo -e "   ${B}[2]${D}  AS ${bold}Full Report${D} (AS Details, Whois/BGP <> Address Space Consistency"
echo -e "   ${B}[3]${D}  Announced Prefixes"
echo -e "   ${B}[4]${D}  AS Peers"
echo -e "   ${B}[5]${D}  Prefix BGP Status"
echo -e "   ${B}[6]${D}  IX Info (Input: IX-ID)"
echo -e "\n\n   ${B}Options > DNS ${D}\n\n"
echo -e "   ${B}[1]${D}  Domain DNS Records ${bold}Summary${D}"
echo -e "   ${B}[2]${D}  Domain DNS Records ${bold}Details${D}"
echo -e "   ${B}[3]${D}  Shared Name Servers"
echo -e "   ${B}[4]${D}  Zone Transfer, Zone Walk"
echo -e "   ${B}[5]${D}  MX SSL Status & Ciphers"
echo -e "   ${B}[6]${D}  dig Batch Mode (Mass DNS Lookup) $denied"
echo -e "\n\n   ${B}Options > HOST INFORMATION\n"
echo -e "   ${B}[1]${D}  Hostname/IP ${bold}Summary${D}"
echo -e "   ${B}[2]${D}  ${bold}Customize${D} Options"
echo -e "   ${B}[3]${D}  Virtual Hosts  ${B}(IPv4)"
echo -e "\n\n   ${B}Options > LOCAL NETWORK OPTIONS (TOOLS: NMAP, THC ATK-6) ${D} $denied\n\n"
echo -e "   ${B}[1]${D}  LAN Discovery (DHCP, Routing, Hosts & Services)  ${B}(IPv4, partial IPv6 support)"
echo -e "   ${B}[2]${D}  Send ARP Broadcast (Host Discovery)              ${B}(IPv4)"
echo -e "   ${B}[3]${D}  Send DHCP Discover Broadcast                     ${B}(IPv4)"
echo -e "   ${B}[4]${D}  Get Router WAN IP via NAT Port Mapping           ${B}(IPv4)"
echo -e "   ${B}[5]${D}  Network & SCADA Services & Vulnerability Scan    ${B}(IPv4)"
echo -e "\n\n  ${B}Options > MTU DISCOVERY ${D}\n\n"
echo -e "  ${B}[m1]${G2}  NMAP     ${D}   MTU Discovery (TCP) using Nmap's path-mtu.nse Script"
echo -e "  ${B}[m2]${G2}  Tracepath${D}   Traceroute & MTU Discovery (ICMP, non-root)"
echo -e "  ${B}[m3]${G2}  atk-trace6${D}  ICMPv6 Traceroute, MTUs- & Tunnel-Discovery"
echo -e "\n\n   ${B}Options > NETWORKS\n\n"
echo -e "   ${B}[1]${D}  Network ${bold}Summary${D}"
echo -e "   ${B}[2]${D}  ${bold}Customize${D} Options"
echo -e "   ${B}[3]${D}  Network ${bold}Report${D} $denied"
echo -e "   ${B}[4]${D}  Prefix Address Space    (Subnets)\n"
echo -e "   ${B}[5]${D}  Reverse DNS Lookup      ${B}(IPv4)"
echo -e "   ${B}[6]${D}  Reverse DNS Lookup      ${B}(IPv6, max-size: /48))"
echo -e "   ${B}[7]${D}  Virtual Hosts (Rev.IP)  ${B}(IPv4)${D}"
echo -e "   ${B}[8]${D}  Ping Sweep              ${B}(IPv4)${D} $denied"
echo -e "   ${B}[9]${D}  Service Banners         ${B}(IPv4)${D}"
echo -e "\n\n  ${B}Options > PING PROBES & PORT SCANS${D}\n\n"
echo -e "  ${B}[p1]${G2}   NPING${D}  Ping Probes  ${B}IPv4${D} ${B}IPv6${D} (ICMP, TCP & UDP)"
echo -e "  ${B}[p2]${G2}   API${D}    Test Ping    ${B}IPv4${D}  (hackertarget.com IP API, API key required)"
echo -e "  ${B}[p3]${G2}   NMAP${D}   Port-, OS/Version- & Vulnerability Scans $denied"
echo -e "  ${B}[p4]${G2}   API${D}    Port Scan    (${B}IPv4${D}  hackertarget.com IP API)"
echo -e "  ${B}[p5]${G2}   NMAP${D}   Firewalk & Basic Firewall Evasion Options $denied"
echo -e "\n\n  ${B}Options > TRACEROUTE${D}\n\n"
echo -e "  ${B}[t1]${G2}   Tracepath${D}          (traceroute & MTUs, non-root) $denied"
echo -e "  ${B}[t2]${G2}   MTR${D}                (RT-Times, Packet Loss, Jitter; TCP,UDP,ICMP) $denied"
echo -e "  ${B}[t3]${G2}   MTR (API)${D}          (hackertarget.com IP API, IPv4 support only)"
echo -e "  ${B}[t4]${G2}   Nmap${D}               (TCP Traceroute & MaxMind Geolocation Data) $denied"
echo -e "  ${B}[t5]${G2}   Dublin Traceroute${D}  (NAT-aware, Multipath Tracerouting) $denied"
echo -e "  ${B}[t6]${G2}   atk-trace6${D}         (ICMPv6 Traceroute MTU- & Tunnel-Discovery) $denied"
f_Long; echo -e "\n${B}Additional Options > ${G2}ROA Validation, Geolocation & whois Summary for each Hop${D}\n"
echo -e "\n\n   ${B}Options > WEB SERVERS $denied\n\n"
echo -e "   ${B}[1]${D}  Server ${bold}Health Check${D}"
echo -e "   ${B}[2]${D}  Server ${bold}Health & Vulnerability Check${D}"
echo -e "   ${B}[3]${D}  ${bold}Customize${D} Test Options"
echo -e "   ${B}[4]${D}  Website Overview"
echo -e "   ${B}[5]${D}  Dump HTTP Headers"
echo -e "   ${B}[6]${D}  Dump SSL Certificate Files & SSL Quick- / Bulk Info"
echo -e "\n\n   ${B}Options > WHOIS ${D}\n\n"
echo -e "   ${B}[1]${G2} RIPE|AFRINIC|APNIC ${B}>${D}  Organisations, Networks & PoCs (inverse & regular searches)\n"
echo -e "   This option is designed for object searches - whois lookups for IP addreses and networks \n   are covered by the network & host options above"
echo -e "\n   By default, this options performs regular lookups. For inverse searches\nenter the object type (e.g. admin-c) and, separated by semicolon, the object name (e.g. BOFH-RIPE.)"
echo -e "A successful search for admin-c;BOFH-RIPE should then return any resource (networks, orgs...) where BOFH-RIPE is \nserving as admin contact."
echo -e "\nInverse search objects have to be unique identifiers (no proper names) of a specified type (nic-handle is not searchable!)."
echo -e "Searching by abuse-c, admin-c, mnt-by, org & tech-c objects is usually most promising.\n"
echo -e "To maximize the yield, options [1] & [2] run a pwhois.org netblock search for any org-object found\n"
echo -e "   ${B}[2]${G2} ARIN               ${B}>${D}  Organisations, Networks & PoCs\n"
echo -e "Expects network addresses (cidr), nethandles, org-ids & e-mail domains (e.g. @ibm.com)\nand returns PoCs, Netranges, Network  & Org-Infos.\n"
echo -e "   ${B}[3]${G2} pwhois.org         ${B}>${D}  Org & NetBlock Searches"
echo -e "   ${B}[4]${G2} pwhois.org         ${B}>${D}  Whois Bulk Lookup (file input)"
echo -e "\nFast mass whois lookup for (announced resources only!). Expected input: file with IP and CIDRs, separated by new line."
echo -e "${B}"; f_Long; echo -e "${G2}\nSOURCES (APIs AND WHOIS SERVERS)${D}\n\n"
echo -e "abusix.com, bgpview.io, certspotter.com, crt.sh,\nhackertarget.com, ip-api.com, isc.sans.edu/api/ip, isc.sans.edu/api/ipdetails"
echo -e "Project Honeypot (https://www.projecthoneypot.org), ripeSTAT Data API (https://stat.ripe.net) \nSublist3r API (https://api.sublist3r.com)"
echo -e "whois.cymru.com, whois.pwhois.org \nRIR whois Servers (whois.afrinic.net, whois.apnic.net, whois.arin.net, whois.lacnic.net, whois.ripe.net)"
echo ''; f_Long; f_Menu
;;
s | r)
#************** ADD Permanent Folder  *******************
f_makeNewDir ; f_Long ; f_REPORT ; f_Menu
;;
#************** ABUSE CONTACT FINDER  *******************
a|ab|abuse|abusec|abusemail|contact|finder|abusefinder)
f_makeNewDir ; target_type="other" ; echo ''; f_Long; out="${outdir}ABUSE_CONTACTS.txt"
echo -e "\n${B}ABUSE CONTACT FINDER >\n"
echo -e -n "${G2}IP ADDRESS / NETWORK ADDRESS (CIDR) / ASN (e.g. as101)  ${B}>>${D}  " ; read input
f_abuse_cFINDER "${input}" | tee -a ${out} ; echo '' | tee -a ${out}; f_removeDir; f_Long; f_Menu
;;
#************** AUTONOMOUS SYSTEMS INFORMATION  *******************
as|asn|asnum|bgp|ix|ixid)
f_makeNewDir ; domain_enum="false"; target_type="as"; f_Long ; f_optionsAS; echo -e -n "\n    ${B}?${D}   " ; read option_as
if ! [ $option_as = "b" ] ; then
if [ $option_as = "1" ] ; then
echo -e "\n${B}Options > ${G2}AS Summary\n"
echo -e "${B} [1]${D} AS Summary" ; echo -e "${B} [2]${D} Announced Prefixes"
echo -e "${B} [3]${D} BOTH" ; echo -e -n "\n   ${B}?${D}  " ; read option_as1
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
as_headline="PREFIXES"; f_asHEADER | tee -a ${out} ; fi
f_bgpPREFIXES ; fi ; done | tee -a ${out}
elif [ $option_as = "5" ] ; then
echo -e -n "\n${B}Target > [1]${D}  Set Target Prefix ${B}| [2]${D}  Target List  ${B}?${D}  " ; read option_target
if [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target > ${G2}PATH TO FILE  ${B}>>${D} " ; read input
targets="$input" ; else
echo -e -n "\n${B}Target > ${G2} BGP PREFIX  ${B}>>${D}  " ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list" ; fi ; out="$outdir/PREFIX_BGP_STATUS.txt"
for p in $(cat $targets | sort -uV); do
curl -s "https://stat.ripe.net/data/network-info/data.json?resource=${p}" > $tempdir/net.json
as=$(jq -r '.data.asns[0]' $tempdir/net.json); echo '' ; f_PREFIX "${p}" ;  done | tee -a ${out}
elif [ $option_as = "6" ] ; then
echo -e -n "\n${B}Target > ${G2} IX ID ${D} - e.g. 25  ${B}>>${D}  " ; read ixid
out="${outdir}/IX.${ixid}.txt" ; curl -s "https://api.bgpview.io/ix/$ixid" > $tempdir/ix.json
f_Long | tee -a ${out}; echo -e " IX | IX-$ixid | $(jq -r '.data.name' $tempdir/ix.json)" | tee -a ${out}
f_Long | tee -a ${out} ; echo '' | tee -a ${out}
jq -r '.data | {Name_short: .name, Descr: .name_full, Members: .members_count, City: .city, Country: .country_code, Website: .website, TechMail: .tech_email, TechPhone: .tech_phone, PolicyMail: .policy_email, PolicyPhone: .policy_phone, Statistics: .url_stats}' $tempdir/ix.json | tr -d '{,"}' |
sed 's/^ *//' | sed '/null/d' | sed '/^$/d' | sed 's/Name_short:/Name:       /' | sed 's/Name_full:/            /' | sed 's/Website:/Website:    /' |
sed 's/TechMail:/TechMail:   /' | sed 's/TechPhone:/TechPhone:  /' | sed 's/PolicyMail:/PolicyMail: /' | sed 's/City:/City:       /' |
sed 's/Country:/Country:    /' | sed 's/Statistics:/Statistics: /' | sed 's/Members:/Members:    /' | sed '/Members:/G' | sed 's/Descr:/Descr:      /' |
sed '/Country:/G' | tee -a ${out}; echo ''; f_Long; echo -e "\n${B}Options > ${G2} List members?\n"
echo -e "${B} [1]${D} ASNs only" ; echo -e "${B} [2]${D} Members, incl. AS Names, Orgs & IP Addresses"
echo -e "${R} [0]${D} BOTH" ; echo -e -n "\n   ${B}?${D}  " ; read option_members
if ! [ $option_members = "0" ] ; then
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo -e "MEMBERS\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' | tee -a ${out}
if [ $option_members = "1" ] ; then
jq -r '.data.members[] | .asn' $tempdir/ix.json | sort -ug | tr '[:space:]' ' ' | sed 's/ /  /' | sed 's/^ *//' | fmt -s -w 60 | sed G | tee -a ${out}
elif [ $option_members = "2" ] ; then
jq -r '.data.members[] | {ASN: .asn, NAME: .name, DESCR: .description, CC: .country_code, IPv4: .ipv4_address, IPv6: .ipv6_address}' $tempdir/ix.json |
tr -d '{,"}' | sed 's/^ *//' | sed '/null/d' | sed '/^$/d' | tr '[:space:]' ' ' | sed 's/ASN:/\nASN:/g' | sort -u | sed 's/ASN: /\n\n/g' |
sed 's/NAME: /\n\n/g' | sed 's/DESCR:/|/g' | sed 's/CC:/|/g' | sed 's/IPv4: /\n\n/g' | sed 's/IPv6://g' | tee -a ${out}
echo -e "\n" | tee -a ${out}; fi; fi; else
echo -e -n "\n\n${B}Target > ${D} AS number -e.g. ${B}AS${D}36459 ${B}>> AS${D}" ; read asnum
as_headline="BGP PREFIXES"
if [ $option_as = "3" ] ; then
out="${outdir}/BGP_PREFIXES.AS.${asnum}.txt"; f_BGPviewPREFIXES | tee -a ${out}; else
out="${outdir}/AS.${asnum}.txt"
echo '' > ${out}; f_Long > ${out}; echo "[+] AUTONOMOUS SYSTEM REPORT $(date)" >> ${out}; f_Long >> ${out}
echo -e "\nCONTENT / SELECTED OPTIONS\n\n" >> ${out}
echo -e "+ AS Overview \n+ AS Points of Contact \n+ Statistics \n+ IX Presence \n+Announced Prefixes" >> ${out}
echo -e "+ Neighbours (Types, Power, AS-Name)" >> ${out}
echo -e "+ Whois <> Address Space / BGP Consistency Checks" >> ${out}
echo -e "+ Announced Prefixes - Net-Names, Reg.Country, ROA Status\n" >> ${out}
f_asINFO | tee -a ${out}; announced=$(jq -r '.data.announced' $tempdir/asov.json)
rir=$(head -1 $tempdir/cyas | awk -F'|' '{print $3}' | tr -d ' ' | sed 's/ripencc/ripe/')
if [ $announced = "true" ] ; then
echo '' | tee -a ${out}; f_BGPviewPREFIXES | tee -a ${out}; fi; fi; fi
echo ''; fi; f_removeDir ; f_Long; f_Menu
;;
#************** BLOCKLISTS / IP REPUTATION CHECKS *******************
bl|rep|reputation|blocklist|blocklists|blacklists|spam)
f_makeNewDir ; f_Long ; touch $tempdir/targets.list ; domain_enum="false"
echo -e "\n${B}Options > Target Types\n"
echo -e "${B} [1]${D} IPv4 Address(es)" ; echo -e "${B} [2]${D} IPv4 Network(s)"
echo -e -n "\n${B}  ?${D}   "; read option_type
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
echo -e "\n" ; f_removeDir ; f_Menu
;;
#************** DOMAIN RECON *******************
d|dom|domain|domains|recon|subs|subdomains)
f_makeNewDir; f_Long; domain_enum="true"; page_details="true"; ssl_details="false"; option_vhosts="true"; request_times="0"
option_dns_details="n"; option_ttl="1"; option_detail="1"; target_type="web"; dns_summary="false"; bl_check="false"
option_ping="0"; blocklists="$blocklists_domain"; eff_url=''; declare -a ns_array=()
echo -e -n "\n${B}Target  > ${G2}DOMAIN  ${B}>>${D}  " ; read x
echo -e -n "\n${B}Option  > ${G2}whois ${B}>${D} Look up whois info for network ranges ${B}[y] | [n] ?${D}  " ; read option_whois
if [ $option_connect = "0" ] ; then
option_testSSL="0"; option_sslscan="0"; option_starttls="0";  option_source="2"; dig_array+=(@9.9.9.9); nssrv="@9.9.9.9"; ww="true"
rfc1912="false"; webpresence="true"; else
handshake_details="true"; option_testSSL="1"; option_sslscan="0"; option_starttls="1"; rep_check="false"; option_source="1"; rfc1912="true"
echo -e "\n${B}Option > ${G2}curl ${B}> ${G2} User Agent\n"
echo -e "${B} [1]${D} default" ; echo -e "${B} [2]${D} $ua_moz" ; echo -e -n "\n${B}  ? ${D}  " ; read option_ua
if [ $option_ua = "2" ] ; then
curl_ua="-A $ua_moz" ; else
curl_ua="" ; fi; fi
if [ $option_connect = "0" ] ; then
pmtu="false"; option_ping="0"; request_times="0"
echo -e "\n${B}Options > ${G2}Zone Transfer\n"
echo -e "${B} [1]${D} ${G2} API ${D}    Check for unauthorized zone transfers"; else
echo -e "\n${B}Options > ${G2}Zone transfer / Load Balancing Detection\n"
echo -e "${B} [1]${D} ${G2} API ${D}    Check for unauthorized zone transfers"
echo -e "${B} [2]${D} ${G2} lbd.sh ${D} Load Balancing Detection"
echo -e "\n${B} [3]${D} BOTH"; fi
echo -e "${R} [0]${D} SKIP" ; echo -e -n "\n${B}  ? ${D}  " ; read option_recon1
echo -e "\n${B}Options > ${G2}RT- & Page-Loading - Times, SSL Ciphers Times, Package Loss, Path-MTU\n"
echo -e "${B} [1]${D} Check Domain Host Connectivity & Response"
echo -e "${B} [2]${D} Get Path-MTUs for Domain Host & DNS Records"
echo -e "\n${B} [3]${D} BOTH"; echo -e "${R} [0]${D} SKIP" ; echo -e -n "\n${B}  ? ${D}  " ; read option_recon2
if [ $option_recon2 = "0" ]; then
pmtu="false"; option_ping="0"; request_times="0"; option_sslscan="0"
elif [ $option_recon2 = "1" ]; then
option_ping="1"; request_times="1"; pmtu="false"; option_sslscan="2"
elif [ $option_recon2 = "2" ]; then
option_ping="0"; request_times="0"; pmtu="true"; option_sslscan="0"
elif [ $option_recon2 = "3" ]; then
option_ping="1"; request_times="1"; pmtu="true"; option_sslscan="2"; fi
echo -e "\n${B}Name Servers (System Defaults)${D}\n" ; f_systemDNS
echo -e "\n\n${B}Options > ${G2}Name Servers\n"; echo -e "${B} [1]${D} Use system defaults"; echo -e "${B} [2]${D} 9.9.9.9"
echo -e "${B} [3]${D} 1.1.1.1"; echo -e "${B} [4]${D} anycast.censurfridns.dk"
echo -e "${B} [5]${D} Set custom NS"; echo -e -n "\n${B}  ? ${D}  "; read option_ns
if [ $option_ns = "2" ] ; then
dig_array+=(@9.9.9.9); nssrv="@9.9.9.9"
elif [ $option_ns = "3" ] ; then
dig_array+=(@1.1.1.1) ;  nssrv="@1.1.1.1"
elif [ $option_ns = "4" ] ; then
dig_array+=(@anycast.censurfridns.dk) ; nssrv="@anycast.censurfridns.dk"
elif [ $option_ns = "5" ] ; then
echo -e -n "\n${B}Set     >${D} NAME SERVER  ${B} >>${D}   " ; read ns_input
dig_array+=(@ns_input); nssrv="@${ns_input}" ; else
nssrv="" ; fi
echo -e "\n${B}Options > ${G2}Subdomains\n"
echo -e "${B} [1]${D} Subdomains (IPv4)" ; echo -e "${B} [2]${D} Subdomains (IPv4, IPv6)"; echo -e -n "\n${B}  ?${D}  "  ; read option_subs
out="$outdir/${x}.txt"; dig_array+=(+noall +answer +noclass +ttlid); f_textfileBanner "${x}" >> ${out}
echo -e "\nCONTENT / SELECTED OPTIONS \n\nTHIS FILE (MAIN FILE)\n" > $tempdir/content
echo "+ Domain & Domain-Website Status" >> $tempdir/content
if [ $option_recon1 = "2" ] || [ $option_recon1 = "3" ]; then
echo "+ Load-balancing Detection (lbd.sh)" >> $tempdir/content; fi
echo "+ Domain hosts (Service Banners, Geolocation, Whois Summary, Virtual Hosts)" >> $tempdir/content
echo -e "+ Website Information:\n  if applicable: CMS, Scripts, Email-/Phone- Contacts & Social Media Links, Meta- & Open Graph Properties)\n  Web Beacons, reverse Google Analytics Search" >> $tempdir/content
if ! [ $option_connect = "0" ]; then
echo -e "+ Server instances\n   Website Hash, Response Times, Security- & Rev. Proxy Headers, Redirects\n+ SSL Certificate Information & Validation (openSSL, testssl.sh)\n+ Domain DNS Records & RFC 1912 Check \n+ MX SSL status" >> $tempdir/content; else
echo -e "+ Certifacte Issuances (via certspotter API)  \n+ Domain DNS Records" >> $tempdir/content; fi
echo -e "+ DNS Records: Geolocation & Whois Summary\n+ DNS Records & Domain Hosts: IP Addresses Reputation Check (IPv4)" >> $tempdir/content
if [ $option_recon1 = "1" ] || [ $option_recon1 = "3" ]; then
echo "+ Zone transfer" >> $tempdir/content; fi
echo -e "+ Subdomains\n+ Prefixes - BGP & RPKI status" >> $tempdir/content
if [ $option_whois = "y" ]; then
echo "+ Network Resources, Organisations, Points of Contact" >> $tempdir/content; fi
echo "+ DNS Records Service Providers (Domains) Overview" >> $tempdir/content
if ! [ $option_connect = "0" ]; then
echo -e "\nIN SEPARATE FILES \n\n+ Full Whois Output\n+ SSL Certificate File Dump\n+ SSL Handshake Details (curl writeout)" >> $tempdir/content
echo -e "\n\nMAIN FILE AND SEPARATE FILES \n\n+ Website Link Dump\n+ HTTP Headers\n+ robots.txt / humans.txt (if applicable)\n+ Website Hashes (SHA1)\n+ Resolved Subdomains (full list)" >> $tempdir/content; else
echo -e "\n\nMAIN FILE && SEPARATE FILE\n\n+ Resolved Subdomains" >> $tempdir/content; fi
cat $tempdir/content >> ${out}; echo '' >> ${out}
if ! [ $option_connect = "0" ] ; then
declare -a st_array=() ; st_array+=(-sLkv)
declare -a curl_array=() ; curl_array+=(-sLkv) ; error_code=6 ; curl -s -f -L -k ${x} > /dev/null
if [ $? = ${error_code} ]; then
echo -e "\n${R} $x WEBSITE CONNECTION: FAILURE${D}\n\n"
echo -e "\n $x WEBSITE CONNECTION: FAILURE\n" >> ${out}
webpresence="false"; option_connect="0" ; f_Long | tee -a ${out} ; f_whoisSTATUS "${x}" | tee -a ${out} ; f_Short | tee -a ${out}
f_DNS_REC "${x}" | tee -a ${out}; f_certINFO "${x}" | tee -a ${out}; option_connect="1" ; else
webpresence="true"; f_writeOUT "${x}" ; f_HEADERS "${x}" > ${outdir}/HEADERS.${x}.txt; fi ; fi
if [ $webpresence = "true" ]; then
curl -s https://api.hackertarget.com/whatweb/?q=${x}${api_key_ht} > $tempdir/ww.txt
if [ $option_connect = "0" ] ; then
eff_url=$(cut -s -d ']' -f 1 $tempdir/ww.txt | sed 's/\[/ /' | tail -1); else
eff_url=$(grep "^URL:" $tempdir/response | cut -d ':' -f 2- | sed 's/^ *//'); fi
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
cat $tempdir/ip4.list | sort -u > $tempdir/ips_all; cat $tempdir/ip6.list | sort -u >> $tempdir/ips_all
f_domainSTATUS "${x}" | tee -a ${out} ; cat $tempdir/domain_status > ${outdir}/WHOIS.${x}.txt
if ! [ $option_connect = "0" ] ; then
if [ $option_recon1 = "2" ] || [ $option_recon1 = "3" ]; then
f_LBD "${x}" | tee -a ${out}
if ! [ "$x" = "$target_host_dom" ] && ! [ "$target4" = "$target_host4" ] ; then
f_LBD "${target_host_dom}" | tee -a ${out}; echo '';fi; echo '' | tee -a ${out}; fi; fi
for a in $(cat $tempdir/ip4.list | sort -uV) ; do
echo ''; f_WEB "${a}"; echo ''; f_BANNERS "${a}"; f_getWHOIS "${a}"; f_WHOIS_OUT "${a}" >> $outdir/WHOIS.${x}.txt; done | tee -a ${out}
if [ -f $tempdir/ip6.list ] ; then
for z in $(cat $tempdir/ip6.list | sort -uV) ; do
f_WEB "${z}" | tee -a ${out};echo '' | tee -a ${out}; f_getWHOIS "${z}"; f_WHOIS_OUT "${z}" >> $outdir/WHOIS.${x}.txt; done; fi
echo '' | tee -a ${out}; for i in $target4 ; do
f_VHOSTS "${i}"; done > $tempdir/reverse_ip
if [[ $(cat $tempdir/reverse_ip | wc -l) -lt 61 ]]; then
cat $tempdir/reverse_ip | tee -a ${out}; fi
echo '' | tee -a ${out}; f_PAGE "${x}" | tee -a ${out}; echo '' | tee -a ${out}
if [ $option_connect = "0" ] ; then
f_certINFO "${x}" | tee -a ${out}; else
declare -a st_array=() ; st_array+=(-s4Lkv); target_type="web" ; target="${x}"
for a in $target4 ; do
echo ''; f_serverINSTANCE "${a}" ; done | tee -a ${out}
if [ -n "$target6" ] ; then
declare -a st_array=() ; st_array+=(-sLkv)
for z in $target6 ; do
echo ''; f_serverINSTANCE "${z}" ; done | tee -a ${out} ; fi
if ! [ "$target4" = "$target_host4" ] ; then
declare -a st_array=() ; st_array+=(-s4Lkv); target_type="web" ; target="${target_host}"
for a in $target_host4 ; do
f_getWHOIS "${a}"; f_WHOIS_OUT "${a}" >> $outdir/WHOIS.${x}.txt ; f_serverINSTANCE "${a}" ;done | tee -a ${out} ; fi
hashes_outfile="WEBSITE_HASHES_$x.$file_date.txt"; f_HASHES_OUT "${x}" >> ${outdir}/$hashes_outfile
if [[ $(cat $tempdir/ips_all | wc -w) -gt 1 ]]; then
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo "WEBSITE HASHES" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' | tee -a ${out}
cat $tempdir/hashes_temp | tee -a ${out}; fi
serial_domain=$(echo | timeout 3 openssl s_client -connect ${x}:443 2>/dev/null | openssl x509 -noout -nocert -serial)
serial_target_host=$(echo | timeout 3 openssl s_client -connect ${target_host}:443 2>/dev/null | openssl x509 -noout -nocert -serial)
cert_dump="true"; f_certINFO "${x}" | tee -a ${out}
if ! [ "$serial_domain" = "$serial_target_host" ] ; then
f_certINFO "${target_host}" | tee -a ${out} ; fi; option_testSSL="0"; cert_dump="false"; fi
echo '' | tee -a ${out}; f_DNS_REC "${x}" | tee -a ${out}
if ! [ "$x" = "$target_host_dom" ] ; then
f_DNS_REC "${target_host_dom}" | tee -a ${out} ; fi
f_NSEC "${x}" | tee -a ${out}; f_FCRDNS "${x}" | tee -a ${out}; f_TTL_ALT "${x}" | tee -a ${out}
if ! [ "$x" = "$target_host_dom" ] ; then
echo '' | tee -a ${out}; f_TTL_ALT "${target_host_dom}" | tee -a ${out}; fi
echo '' | tee -a ${out}; target_type="dnsrec"; type_mx="true"; f_DNSdetails "${x}" | tee -a ${out} ; type_mx="false"
blocklists="$blocklists_domain"; echo ''  | tee -a ${out}; f_Long | tee -a ${out}
echo "[+] DNS RECORDS | IP REPUTATION CHECK" | tee -a ${out}; f_Long | tee -a ${out}; echo -e "\nChecking ...\n" | tee -a ${out}
echo -e "$blocklists_domain" | sed '$!s/$/,/' | sed '1,1d' | tr '[:space:]' ' ' | fmt -s -w 90 | tee -a ${out}
echo -e "Project Honeypot, Stop Forum SPAM, Spamhaus ZEN, Grey Noise Community API & SANS Internet Storm Center\n" | tee -a ${out}
for i in $(cat $tempdir/ips.list | sort -uV); do
f_IP_REPUTATION "${i}" ; done | tee -a ${out}
if [ -f $tempdir/isc ] ; then
echo  -e "________________________________________________\n" | tee -a ${out}
echo -e "\nGetting results from SANS Internet Storm Center Threatfeeds for DNS Records...\n\n" | tee -a ${out}
cat $tempdir/isc | tee -a ${out} ; fi ; echo '' | tee -a ${out}
if [ $option_recon1 = "1" ] || [ $option_recon1 = "3" ]; then
f_AXFR "${x}" | tee -a ${out}
if ! [ "$x" = "$target_host_dom" ] ; then
f_AXFR "${target_host_dom}" | tee -a ${out} ; fi ; else
echo '' | tee -a ${out} ; fi
f_subs_HEADER "${x}" | tee -a ${out}
if [ $option_whois = "y" ] ; then
f_Long | tee -a ${out} ; echo -e "\nReminder:  Network names are not considered unique identifiers." | tee -a ${out}
echo -e "Watch out for false positives within the 'Resources for' sections.\n" | tee -a ${out}
cat $tempdir/domain_nets | tee -a ${out} ; fi
if ! [ $option_connect = "0" ] ; then
echo '' | tee -a ${out}; cat ${outdir}/HEADERS.${x}.txt | tee -a ${out}; echo '' | tee -a ${out}
cat ${outdir}/LINK_DUMP.${x}.txt | tee -a ${out}; echo '' | tee -a ${out}; fi
if [[ $(cat $tempdir/reverse_ip | wc -l) -gt 60 ]]; then
cat $tempdir/reverse_ip | tee -a ${out}; fi
if [ -f ${outdir}/SUBDOMAINSall_v4.$x.txt ] ; then
cat ${outdir}/SUBDOMAINSall_v4.$x.txt | tee -a ${out} ; else
cat ${outdir}/Subdomains_HT.${x}.txt | tee -a ${out}; fi
if [ $option_subs = "2" ] ; then
cat ${outdir}/SUBS.v6.$x.txt | tee -a ${out}; fi
if [ -f $tempdir/provider_domains ]; then
echo '' | tee -a ${out}; cat $tempdir/provider_domains | tee -a ${out}; fi; fi
echo -e "\n" ; f_removeDir ; f_Long; f_Menu
;;
#************** DNS OPTIONS *******************
dns|mx|ns|zone|zonetransfer|dig|nslookup|nsec)
f_makeNewDir; f_Long; domain_enum="false"; option_detail="1"; bl_check="false"
cert_dump="false"; quiet_dump="false"; option_testSSL="0"; type_mx="true"; declare -a dig_array=() ; f_optionsDNS
echo -e -n "\n    ${B}?${D}   "; read option_dns
if ! [ $option_dns = "b" ] ; then
if [ $option_dns = "1" ] ; then
dns_summary="true" ; else
dns_summary="false" ; fi
if [ $option_dns = "3" ] ; then
target_type="web"; else
target_type="dnsrec"; fi
#************** SHARED NAME SERVERS *******************
if [ $option_dns = "3" ] ; then
echo -e -n "\n${B}Shared NS > Target >${G2} NAME SERVER ${B}>>${D}  " ; read targetNS ; echo ''
out="${outdir}/SharedNameserver_${targetNS}.txt" ; echo '' | tee -a ${out}
f_Long | tee -a ${out}; echo -e "[+] $targetNS  |  SHARED NS  ($file_date)" | tee -a ${out}; f_Long | tee -a ${out}
f_nsSHORT "${targetNS}" | tee -a ${out}
curl -s "https://api.hackertarget.com/findshareddns/?q=${targetNS}${api_key_ht}" > $tempdir/sharedns
f_Long | tee -a ${out}; echo -e "DOMAINS: $(cat $tempdir/sharedns | wc -l)\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' | tee -a ${out}
if [[ $(cat $tempdir/sharedns | wc -l) -lt 701 ]] ; then
echo -e "Resolving results...\n"
dig @anycast.censurfridns.dk +noall +answer +noclass +nottlid -f $tempdir/sharedns > $tempdir/sharedns_hosts
grep 'A' $tempdir/sharedns_hosts | sed '/NS/d' | sed '/CNAME/d' | awk '{print $1,"\n\t\t\t\t",$3}'
grep 'A' $tempdir/sharedns_hosts | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' |
sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n -u > $tempdir/ips_sorted
if [[ $(cat $tempdir/ips_sorted | wc -l) -lt 101 ]] ; then
cat $tempdir/ips_sorted > $tempdir/ips_sorted.list; else
cat $tempdir/ips_sorted | sort -t . -k 1,1n -k 2,2n -k 3,3n -u > $tempdir/ips_sorted.list; fi
echo '' | tee -a ${out}; f_whoisTABLE "$tempdir/ips_sorted.list"; f_Long | tee -a ${out}; echo "[+] pwhois Bulk Lookup" | tee -a ${out}
f_Long | tee -a ${out}; cat $tempdir/whois_table.txt | cut -d '|' -f -5 | sed '/^$/d' | sed '/NET NAME/{x;p;x;G}' | tee -a ${out}
asns=$(cut -d '|' -f 1 $tempdir/whois_table.txt | grep -E -v "AS|NA" | sed '/^$/d' | tr -d ' ' | sort -uV)
if [ -n "$asns" ]; then
echo -e "\n___________________________________________________________\n\n" | tee -a ${out}
for as in $asns ; do
asn=$(dig +short as$as.asn.cymru.com TXT | tr -d "\"" | sed 's/^ *//' | cut -d '|' -f 1,5 | sed 's/ |/,/g'); echo -e "AS $asn"; done | tee -a ${out}; fi
if [[ $(cat $tempdir/ips_sorted | wc -w) -lt 301 ]] ; then
echo ''; f_Long
echo -e -n "\n${B}Option  > ${D} Run IP Reputation Check against $(cat $tempdir/ips_sorted | wc -w) individual Hosts ${B}?  [y] | [n] ${D}  "
read option_rep; echo '' | tee -a ${out}
if [ $option_rep = "y" ] ; then
blocklists="$blocklists_host"
f_Long | tee -a ${out}; echo -e "[+] IP REPUTATION CHECK" | tee -a ${out}; fi
for a in $(cat $tempdir/ips_sorted); do
f_Long; echo -e "$a" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
f_BOGON "${a}"
if [ $bogon = "TRUE" ] ; then
echo -e "\n! BOGON Address:       $a !\n" ; else
rdns=$(dig +short -x $a); reverse=$(echo $a | awk -F'.' '{printf $4 "." $3 "." $2 "." $1}')
abx=$(dig +short $reverse.abuse-contacts.abusix.zone txt | tr -d '/"'| sed 's/^ *//' | tr '[:space:]' ' '; echo '')
echo "[@]:  $abx"; echo -e "___\n"
if [ $option_rep = "y" ] ; then
echo ''; f_IP_REPUTATION "${a}"; echo ''; fi
if [ -n "$rdns" ]; then
echo -e "\n* rDNS\n"
echo "$rdns" | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -s -w 80; echo ''; fi ; fi
echo -e "\n* HOSTS\n"
grep -E "${a}" $tempdir/sharedns_hosts | awk '{print $1}' | rev | cut -c 2- | rev | tr '[:space:]' ' ' | sed 's/ /  /g' |
sed 's/^ *//' | fmt -s -w 80; echo -e "\n"; done | tee -a ${out}; fi; else
echo '' | tee -a ${out} ; cat $tempdir/sharedns | tee -a ${out}; echo '' | tee -a ${out}; fi
#************** ZONE TRANSFER / ZONE WALK *******************
elif [ $option_dns = "4" ] ; then
if [ $option_connect = "0" ] ; then
echo -e "\n${B}Options > ${G2}Zone Transfer / Zone Walk${B}\n"
echo -e " ${B}[1] ${G2} API  ${B} Zone Transfer${D}  (probes all NS records)"
echo -e " ${B}[2] ${G2} dig  ${B} Zone Transfer${D}  (probes all or specific domain name servers)"
echo -e " ${B}[3] ${G2} Nmap ${B} Zone Walk${D}"
echo -e -n "\n${B}  ? ${D}  " ; read option_xfr ; fi
if [ $option_xfr = "3" ] ; then
echo -e -n "\n${B}Target >${G2} NAME SERVER ${B}>>${D}  " ; read target_ns
out="${outdir}/ZONE_WALK.$target_ns.txt"
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo "[+] $target | ZONEWALK | NS: $target_ns | $(date)" | tee -a ${out} ; f_Long | tee -a ${out}
echo '' | tee -a ${out}
sudo ${PATH_nmap} -sSU -p 53 --script dns-nsec-enum --script-args dns-nsec-enum.domains=$target $target_ns | tee -a ${out}
elif [ $option_xfr = "2" ] ; then
echo -e -n "\n${B}Target >${G2} DOMAIN ${B}>>${D}  " ; read target
out="${outdir}/ZONE_TRANSFER.$target.txt"
echo -e "\n${B}$target NS Records${D}\n\n"
dig ns +short $target | rev | cut -c  2- | rev | tee $tempdir/ns.txt
echo -e -n "\n\n${B}Server > [1]${D} All NS records ${B}| [2]${D} specific name server  ${B}?${D}  " ; read option_ns
if  [ $option_ns = "2" ] ; then
echo -e -n "\n${B}Target >${G2} NAME SERVER ${B}>>${D}  " ; read target_ns ; echo ''; fi
f_Long | tee -a ${out}; echo "[+] $target | ZONE TRANSFER | $(date)" | tee -a ${out}; echo '' | tee -a ${out}
if  [ $option_ns = "2" ] ; then
dig axfr @${target_ns} $target | sed '/;; global options:/d' | sed '/;; Query time:/{x;p;x;}' | sed '/server found)/G' | tee -a $out ; else
for i in $(cat $tempdir/ns.txt); do
dig axfr @${i} $target | sed '/;; global options:/d' | sed '/;; Query time:/{x;p;x;}' | sed '/server found)/G' ; done | tee -a ${out} ; fi ; else
echo -e -n "\n${B}Target >${G2} DOMAIN ${B}>>${D}  " ; read target
out="${outdir}/ZONE_TRANSFER.$target.txt"; echo '' | tee -a ${out}; f_Long | tee -a ${out}
echo "[+] $target | ZONE TRANSFER | $(date)" | tee -a ${out}; f_Long | tee -a ${out}
curl -s https://api.hackertarget.com/zonetransfer/?q=${x}${api_key_ht} > $tempdir/zone.txt
echo -e "\nSource: hackertarget.com IP API\n" >> $tempdir/zone.txt; cat $tempdir/zone.txt | tee -a ${out} ; fi
#************** MAIL SERVER SSL/TLS *******************
elif [ $option_dns = "5" ] ; then
dig_array+=(@9.9.9.9); dig_array+=(+noall +answer +noclass +ttlid); option_sslscan="3"; type_mx="true"
echo -e "\n${B}Options > ${G2}MX SSL \n"
echo -e "${B} [1]${D}  Domain MX Records - SSL Status & Ciphers"
echo -e "${B} [2]${D}  Mail Server (not domain-specific) - SSL Status & Ciphers"
echo -e -n "\n${B}  ?${D}   "  ; read option_type
if [ $option_type = "1" ] ; then
option_starttls="1"
echo -e -n "\n${B}Target  > ${G2}DOMAIN  ${B}>>${D}  " ; read target_domain
out="${outdir}/MX_SSL.$target_domain.txt"
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo "[+]  $target_domain  |  MX SSL" | tee -a ${out}; f_Long | tee -a ${out}
f_MX "${target_domain}" | tee -a ${out}; mxs=$(awk '{print $NF}' $tempdir/mxservers.list)
mx_4=$(egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/mx4.list | sort -uV)
if [ -n "$mx_4" ] ; then
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo -e "PTR RECORDS\n" | tee -a ${out}
for a in $mx_4; do
ptr=$(host $a 9.9.9.9 | grep -E "name pointer" | rev | cut -d ' ' -f 1 | rev | tr '[:space:]' ' ')
if [ -n "$ptr" ] ; then
echo -e "$a \n\n     $ptr\n" ; else
echo -e "$a \n\n     no PTR record\n" ; fi ; done | tee -a ${out}
if [ -n "$mx_6" ]; then
for z in "$mx_6"; do
ptr=$(host $z 9.9.9.9 | grep -E "name pointer" | rev | cut -d ' ' -f 1 | rev | tr '[:space:]' ' ')
if [ -n "$ptr" ] ; then
echo -e "$z \n\n     $ptr\n" ; else
echo -e "$z \n\n     no PTR record\n" ; fi ; done | tee -a ${out}; fi; fi
echo '' | tee -a ${out}
for m in $mxs ; do
f_certINFO "${m}" | tee -a ${out} ; done ; else
echo -e "\n${B}Options > ${G2} MX > STARTTLS \n"
echo -e "${B} [1]${D} SMTP" ; echo -e "${B} [2]${D} IMAP"
echo -e -n "\n${B}  ?${D}   "  ; read option_starttls
echo -e -n "\n${B}Target  > [1]${D}  Set Target ${B}| [2]${D}  Target List  ${B}?${D}  " ; read option_target
if [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target  > ${G2}PATH TO FILE ${D}- e.g. ./hosts.list  ${B}>>${D} " ; read input
targets="$input" ; else
echo -e -n "\n${B}Target  > ${G2}HOSTNAME/IP ADDRESS${B}>>${D}  " ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/hosts.list" ; fi
for x in $(cat $targets | sort -u); do
out="${outdir}/MX_SSL.$x.txt"
f_dnsFOR_CHAIN "${x}" | tee -a ${out}
f_certINFO "${x}" | tee -a ${out} ; f_CLEANUP_FILES; done ; fi
#************** DIG BATCH MODE (DNS MASS LOOKUP) *******************
elif [ $option_dns = "7" ] ; then
echo -e "\n${B}Options > dig >${D} Queries/ Record Types\n "
echo -e "${B} [1]${D} A" ; echo -e "${B} [2]${D} AAAA"
echo -e "${B} [3]${D} NS"; echo -e "${B} [4]${D} MX"
echo -e "${B} [5]${D} SRV"; echo -e "${B} [6]${D} ANY"
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
dig ${dig_array[@]} -f ${input} | tee -a ${out} ; echo '' | tee -a ${out} ; else
if [ $option_dns = "6" ] ; then
option_dns_nmap="true"; fi
echo -e -n "\n${B}Target  > [1]${D} Set target Domain ${B}| [2]${D} Target List  ${B}?${D}  " ; read option_target
if [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target  > ${G2}PATH TO FILE ${D}- e.g. ./domains.list ${B}>>${D}  " ; read input
hosts="${input}" ; else
echo -e -n "\n${B}Target  > ${G2}DOMAIN  ${B}>>${D}  " ; read input
echo "$input" > $tempdir/hosts.list ; hosts="$tempdir/hosts.list" ; fi
#************** DOMAIN DNS RECORDS *******************
if [ $option_dns = "1" ] || [ $option_dns = "2" ]; then
blocklists="$blocklists_domain"; echo -e "\n${B}Nameservers (System Defaults)${D}\n" ; f_systemDNS
echo -e "\n\n${B}Options > Settings > ${G2}Name Server\n"
echo -e "${B} [1]${D} Use system defaults" ; echo -e "${B} [2]${D} 9.9.9.9"
echo -e "${B} [3]${D} 1.1.1.1" ; echo -e "${B} [4]${D} anycast.censurfridns.dk"
echo -e "${B} [5]${D} Set custom NS" ; echo -e -n "\n${B}  ? ${D}  " ; read option_ns
if [ $option_ns = "2" ] ; then
dig_array+=(@9.9.9.9) ; nssrv="@9.9.9.9"
elif [ $option_ns = "3" ] ; then
dig_array+=(@1.1.1.1) ; nssrv="@1.1.1.1"
elif [ $option_ns = "4" ] ; then
dig_array+=(@anycast.censurfridns.dk) ; nssrv="@anycast.censurfridns.dk"
elif [ $option_ns = "5" ] ; then
echo -e -n "\n${B}Set     >${D} NAME SERVER  ${B} >>${D}   " ; read ns_input
dig_array+=(@nssrv) ; nssrv="@${ns_input}" ; else
nssrv="" ; fi; dig_array+=(+noall +answer +noclass)
if [ $dns_summary = "true" ] ; then
option_ttl="1"; rfc1912="false"; option_bl="n"; option_dns_details="n"; option_dns_nmap="false"; else
option_dns_details="y"; option_bl="n"; blocklists="$blocklists_domain"; option_starttls="1"
echo -e "\n${B}Options > ${G2} TTL\n"; echo -e "${B} [1]${D} TTL values (ms)"
echo -e "${B} [2]${D} TTL values (human readable)"; echo -e -n "\n${B}  ? ${D}  " ; read option_ttl
echo -e "\n${B}Option  > ${G2}Zone Transfer${D}\n"
echo -e "${B} [1]${G2} API ${D}Check for unauthorized zonetransfers"
echo -e "${R} [0]${D}     SKIP" ; echo -e -n "\n${B}  ? ${D}  " ; read option_zone
if [ $option_connect = "0" ] ; then
option_sslscan="0"; rfc1912="false"; option_dns_nmap="false"; else
rfc1912="true"; option_dns_nmap="true"
echo -e "\n${B}Options > ${G2} MX SSL CERTS\n"
echo -e "${B} [1]${D} MX SSL certificates - status & summary"
echo -e "${B} [2]${D} MX SSL certificates - status, summary & SSLscan"
echo -e "${R} [0]${D} SKIP" ; echo -e -n "\n${B}  ? ${D}  " ; read option_mxssl
if [ $option_mxssl = "2" ] ; then
option_sslscan="3"; else
option_sslscan="0"; fi ; fi ; fi; fi
if [ $option_dns_nmap = "true" ]; then
f_Long; echo -e "${B}Option  > ${G2} Raw Socket Priviliges (root-/sudo-users only)${D}\n"
echo -e "Required for\n"
if [ $option_dns = "2" ]; then
echo -e "MTU Discovery"; fi
echo -e "Nmap Version- / OS- Detection & Vulnerability Scans"
echo -e -n "\n${G2}Run Applications with elevated priviliges ${B}[y] | [n]  ?${D}  " ; read option_root
if [ $option_root = "n" ]; then
option_nse="0"; pmtu="false"; else
if [ $option_dns = "2" ]; then
pmtu="true"; fi; echo -e "\n${B}Options > MX / NS VULNERABILITY SCAN ${B} > ${G2} Nmap Script Categories\n"
echo -e "${B} [1]${D} Safe" ; echo -e "${B} [2]${D} Intrusive FAST"; echo -e "${B} [3]${D} Intrusive SLOW"
if [ $option_dns = "2" ]; then
echo -e "${R} [0]${D} SKIP"; fi
echo -e -n "\n${B}  ?${D}   "  ; read option_nse
ports="${ports_dns}"; nmap_array+=(-Pn -sV -sS -sU --version-intensity 4 -R --resolve-all --open)
if [ $option_nse = "1" ]; then
ports="U:53,T:53,T:23,T:25,T:110,T:143,T:443,T:465,T:587,T:993,T:995"
scripts="--script=${nse_dns_01}"; script_args="--script-args smtp-commands.domain=$x"
elif [ $option_nse = "2" ]; then
ports="U:53,T:53,T:23,T:25,T:110,T:143,T:443,T:465,T:587,T:993,T:995"
scripts="--script=${nse_dns_01},${nse_dns_02}"; script_args="--script-args smtp-commands.domain=$x"
elif [ $option_nse = "3" ]; then
ports="U:53,T:53,T:22,T:23,T:25,T:80,T:110,T:143,T:443,T:465,T:587,T:993,T:995"
scripts="--script=${nse_dns_01},${nse_dns_02},${nse_dns_03}"; script_args="--script-args smtp-commands.domain=$x,http-methods.test-all"; fi; fi; fi
for x in $(cat $hosts) ; do
if [ $option_dns = "1" ] || [ $option_dns = "2" ]; then
if [ $dns_summary = "true" ] ; then
out="${outdir}/DNS_SUMMARY.$x.txt"; f_DNS_REC "${x}" | tee -a ${out}; else
out="${outdir}/DNS.$x.txt"; f_DNS_REC "${x}" | tee -a ${out}
if ! [ $option_connect = "0" ] ; then
if [ $option_mxssl = "1" ] || [ $option_mxssl = "2" ] ; then
echo -e "\n" | tee -a ${out}; f_Long | tee -a ${out} ; echo "[+]  MX  |  SSL/TLS" | tee -a ${out}
mx_servers=$(awk '{print $NF}' $tempdir/mxservers.list | sed 's/.$//' | sort -uV)
for m in $mx_servers ; do
f_certINFO "${m}"  ; done | tee -a ${out}; type_mx="false"; fi ; fi
if [ $option_zone = "1" ]; then
f_AXFR "${x}" | tee -a ${out}; fi; echo ''  | tee -a ${out}
f_DNSdetails "${x}" | tee -a ${out}; echo ''  | tee -a ${out}; f_Long | tee -a ${out}; echo "[+] DNS RECORDS | IP REPUTATION LOOKUP" | tee -a ${out}
f_Long | tee -a ${out}; echo -e "\nChecking ...\n" | tee -a ${out}
echo -e "$blocklists_domain" | sed '$!s/$/,/' | sed '1,1d' | tr '[:space:]' ' ' | fmt -s -w 90 | tee -a ${out}
echo -e "Project Honeypot, Stop Forum SPAM, Spamhaus ZEN, Grey Noise Community API" | tee -a ${out}
echo '' | tee -a ${out}
for i in $(cat $tempdir/rec_ips.list | sort -uV); do
echo  -e "________________________________________________\n"; f_IP_REPUTATION "${i}"; done | tee -a ${out}; fi; fi
if [ $option_dns = "2" ] || [ $option_dns = "6" ]; then
if ! [ $option_connect = "0" ] && ! [ $option_nse = "0" ]; then
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo "[+] $target_domain NS RECORDS" | tee -a ${out}
for n in $(dig ns +short $target_domain | rev | cut -c 2- | rev); do
option_ipv="1"; f_RUN_NMAP "${n}"; ns_6=$(dig aaaa +short $n)
if [ -n "$ns_6" ]; then
option_ipv="2"; f_RUN_NMAP "${n}"; fi; done | tee -a ${out}
for m in $(dig mx +short $target_domain | rev | cut -d ' ' -f 1 | cut -c 2- | rev); do
mx_4=$(dig a +short $m); mx_6=$(dig aaaa +short $m)
if [ -n "$mx_4" ]; then
option_ipv="1"; f_RUN_NMAP "${m}"; fi
if [ -n "$mx_6" ]; then
option_ipv="2"; f_RUN_NMAP "${m}"; fi; done | tee -a ${out}; fi; fi
if [ $option_dns = "2" ] && ! [ $option_connect = "0" ]; then
echo '' | tee -a ${out}; f_Long | tee -a ${out}
echo -e "\nDNS DELEGATION  (DOMAIN HOST A)\n\n" | tee -a ${out}
dig ${nsserv} +noall +answer +trace +dnssec +noclass +nottlid +nocrypto $x | sed '/;;/{x;p;x;}' | sed '/\tA\t/{x;p;x;G}' |
sed '/;; Received/G' | sed 's/;; Received/Received/g' | fmt -s -w 120 | tee -a ${out}; fi
if [ -f $tempdir/provider_domains ]; then
cat $tempdir/provider_domains; fi; done; fi; fi
echo -e "\n" ; f_removeDir; f_Long; f_Menu
;;
#***************** REVERSE GOOGLE ANALYTICS SEARCH *****************
g|google|analytics)
f_makeNewDir ; f_Long
echo -e -n "${B}\nTarget > ${G2} Google Analytics ID ${B}>${D}  e.g. UA-123456 or pub-00123456789 ${B}>>${D}  " ; read gooid
out="$outdir/Rev_GoogleAnalytics.txt"
echo -e "\n" | tee -a "${out}"; f_Long | tee -a ${out}
echo -e " $gooid | REVERSE GOOGLE ANALYTICS LOOKUP" | tee -a  ${out} ; f_Long | tee -a ${out}
curl -s https://api.hackertarget.com/analyticslookup/?q=${gooid} | tee -a ${out}
echo -e "\nSource > hackertarget.com\n" | tee -a ${out} ; echo -e "\n"; f_removeDir; f_Long; f_Menu
;;
#************** PUBLIC IP ADDRESS, NETWORK INTERFACES, DEFAULT ROUTES & NS *******************
i)
f_makeNewDir; target_type="other"; domain_enum="false"
echo -e "\n${B}Option  > ${G2} Public IP Addresses${D}\n"
echo -e "${B} [1]${D} Look up BGP, Whois-, Geolocation- & IP Reputation- Info"
echo -e "${R} [0]${D} SKIP"; echo -e -n "\n${B}  ? ${D}  " ; read option_pub_ip
out="${outdir}/LOCAL_SYSTEM.txt" ; echo '' | tee -a ${out}; f_Long | tee -a ${out}
echo "[+] LOCAL SYSTEM SUMMARY | $(date)" | tee -a ${out} ; f_Long | tee -a ${out}
echo -e "\nUser:                $(whoami)" | tee -a ${out}
echo -e "\nGroups:              $(groups)" | tee -a ${out}
echo -e "\nMachine:             $(uname -n) | OS: $(uname -o), $(uname -r)\n" | tee -a ${out}
if ! [[ $(uname -o) =~ "Android" ]] ; then
echo '' | tee -a ${out} ; lspci | grep -E "Network|Ethernet" | cut -d ' ' -f 2- | sed 's/Network controller:/Network controller: /' |
sed '/Network controller:/G' | tee -a ${out} ; echo '' | tee -a ${out}; fi
f_IFLIST
f_Long | tee -a ${out}; echo -e "PUBLIC IP ADDRESSES" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' | tee -a ${out}
for nic4 in $(ip -4 addr show | grep -s 'state UP' | cut -d ':' -f 2 | sed 's/^ *//'); do
echo -e "\n\nPublic IPv4:         $(curl -s -m 5 --interface $nic4 https://api.ipify.org?format=json | jq -r '.ip')  ($nic4)"; done > $tempdir/pub4
cat $tempdir/pub4 | tee -a ${out}; pub4=$(egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/pub4)
for nic6 in $(ip -6 addr show | grep -s 'state UP' | cut -d ':' -f 2 | sed 's/^ *//'); do
addr_v6=$(ip -6 addr show | grep -Es -A 3 "${nic6}" | grep inet6 | sed 's/^ *//' | cut -d ' ' -f 2 | cut -d '/' -f 1 | grep ':' | sort -u)
for addr in $addr_v6; do
f_BOGON "${addr}"
if [ $bogon = "FALSE" ]; then
echo -e "\n\nPublic IPv6:         $addr  ($nic6)"; echo "$addr" >> $tempdir/pub6; fi; done; done | tee -a ${out}
if [ -f $tempdir/pub6 ]; then
pub6=$(cat $tempdir/pub6 | sort -uV); fi
echo '' | tee -a ${out}
if [ $option_pub_ip = "1" ]; then
bl_check="true"; option_root="n"; option_trace="n"; blocklists="$blocklists_domain"
for a in $(egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/pub4 | sort -uV); do
f_WEB "${a}"; echo '' ; f_Long; echo -e "\nDNS" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; ptr=$(dig +short -x $a)
if [ -n "$ptr" ]; then
f_dnsFOR_CHAIN "${a}"; else
echo -e "$a - no PTR record\n"; fi; f_DELEGATION "${a}" > $tempdir/rdnszone
if [[ $(cat $tempdir/rdnszone | wc -l) -gt 2 ]]; then
echo -e "\nREV.DNS DELEGATION\n"; cat $tempdir/rdnszone | sed '/./,$!d'; fi; done | tee -a ${out}
if [ -n  "$pub6" ]; then
echo -e "\n" | tee -a ${out}; for z in $pub6; do
f_WEB "${z}"; echo '' ; f_Long; echo -e "DNS\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; ptr=$(dig +short -x $z)
if [ -n "$ptr" ]; then
f_dnsFOR_CHAIN "${z}"; else
echo -e "$z - no PTR record\n"; fi; f_DELEGATION "${z}" > $tempdir/rdnszone
if [[ $(cat $tempdir/rdnszone | wc -l) -gt 2 ]]; then
echo -e "\nREV.DNS DELEGATION\n"; cat $tempdir/rdnszone | sed '/./,$!d'; fi; done | tee -a ${out}; fi; fi
if ! [[ $(uname -o) =~ "Android" ]] ; then
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo -e "\n******************** DEFAULT DNS SERVERS *******************" | tee -a ${out}
f_systemDNS | tee -a ${out} ; fi; echo '' ; f_removeDir; f_Long; f_Menu
;;
#************** IP ADDRESS / HOST INFORMATION *******************
host|ip)
f_makeNewDir; f_Long; touch $tempdir/targets.list; domain_enum="false"; blocklists="$blocklists_host"; option_connect="0"; option_source="2"
target_type="default"; f_optionsHOSTS; echo -e -n "\n${B}    ?${D}   "  ; read option_enum1
if ! [ $option_enum1 = "b" ] ; then
if ! [ $option_enum1 = "2" ] ; then
option_enum2="1"; option_enum3="0"; option_enum4="0"; option_enum5="0"; option_detail="1"; option_bl="n"; option_banners="false"
ww="false"; else
echo -e "\n${B}Options > \n"
echo -e "${B} [1]${D} IPv4 Address" ; echo -e "${B} [2]${D} IPv6 Address"
echo -e "${B} [3]${D} Hostname" ; echo -e -n "\n${B}  ?${D}   "  ; read option_type
f_Long; echo -e "\n${B}Options  > ${G2}Network Admin Contacts (Whois)\n"
echo -e "${B} [1]${D} Summary"; echo -e "${B} [2]${D} Details"; echo -e -n "\n${B}  ? ${D}  " ; read option_enum2
if [ $option_enum2 = "1" ] ; then
option_detail="1"; else
option_detail="2"; fi
if [ $option_type = "2" ] ; then
option_enum3="0"; option_enum4="0"; option_enum5="0"; else
echo -e "\n${B}Options > ${G2}Banners/IP Reputation\n"
echo -e "${B} [1]${D} Banner Grab"
echo -e "${B} [2]${D} IP Reputation Check"
echo -e "${B} [3]${D} BOTH" ; echo -e "${R} [0]${D} SKIP"
echo -e -n "\n${B}  ? ${D}  " ; read option_enum3
if [ $option_enum3 = "1" ] ; then
option_banners="true"; option_bl="n"
elif [ $option_enum3 = "2" ] ; then
option_bl="y" ; option_banners="false"
elif [ $option_enum3 = "3" ] ; then
option_bl="y"; option_banners="true"; else
option_bl="n"; option_banners="false"; fi
if [ $option_type = "3" ] ; then
echo -e "\n${B}Option  > ${G2}Certificates\n"
echo -e "${B} [1]${D} List target certificate issuances  (Certspotter API)"
echo -e "${R} [0]${D} SKIP"; echo -e -n "\n${B}  ? ${D}  " ; read option_enum4
echo -e "\n${B}Options > ${G2}WhatWeb  ${B}(hackertarget.com API)\n"
echo -e "${B} [1]${D} Run Whatweb against target"
if [ $option_banners = "true" ]; then
echo -e "${B} [2]${D} Run Whatweb against target if Banner Grab identifies target as web server" ; fi
echo -e "${R} [0]${D} SKIP"; echo -e -n "\n${B}  ? ${D}  " ; read option_enum5; fi; fi; fi
if [ $option_enum1 = "1" ] ; then
echo -e -n "\n${B}Target  > [1]${D}  Set Target Hostname / IPv4-/IPv6-Address ${B}| [2]${D}  Target List  ${B}?${D}  " ; read option_target
elif [ $option_enum1 = "3" ] ; then
echo -e -n "\n${B}Target  > [1]${D}  Set Target Hostname / IPv4-Address ${B}| [2]${D}  Target List  ${B}?${D}  " ; read option_target; else
echo -e -n "\n${B}Target  > [1]${D}  Set Target ${B}| [2]${D}  Target List  ${B}?${D}  " ; read option_target; fi
if [ $option_target = "1" ] ; then
echo -e -n "\n${G2}TARGET  ${B}>>${D}  " ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list"
elif [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target  > ${G2}PATH TO FILE ${D} -  e.g. ./hosts.list  ${B}>>${D}  " ; read input
targets="$input" ; fi
for t in $(cat $targets | sort -uV) ; do
echo ''; x=$(echo $t | sed 's/http[s]:\/\///' | cut -d '/' -f 1 | tr -d ' ')
if ! [ $option_enum1 = "2" ]; then
option_detail="1"; option_banners="false"; option_bl="n"; ww="false"
if [[ ${x} =~ ":" ]] ; then
option_type="2"
elif [[ ${x} =~ $REGEX_IP4 ]] ; then
option_type="1" ; else
option_type="3"; fi; fi
if [ $option_enum1 = "3" ] ; then
out="${outdir}/REVERSE_IP.${x}.txt"; else
out="${outdir}/HOST_INFO.${x}.txt"; fi
if [ $option_type = "3" ] ; then
host4=$(dig @anycast.censurfridns.dk +short $x); host6=$(dig @anycast.censurfridns.dk aaaa +short $x)
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo "[+]  $x" | tee -a ${out}
if [ $option_enum1 = "3" ] ; then
f_dnsFOR_CHAIN "${x}" | tee -a ${out}; else
f_DNSWhois_STATUS "${x}" | tee -a ${out}; fi
if [ $option_enum5 = "1" ]; then
curl -s https://api.hackertarget.com/whatweb/?q=${x}${api_key_ht} > $tempdir/ww.txt
f_PAGE "${x}" | tee -a ${out}; fi
if [ -n "$host4" ] ; then
for a in $host4 ; do
if [ $option_enum1 = "3" ] ; then
f_VHOSTS "${a}" | tee -a ${out}; else
f_hostDEFAULT "${a}" | tee -a ${out}; fi; f_CLEANUP_FILES; done; fi
if [ -n "$host6" ] ; then
for z in $host6; do
f_hostDEFAULT "${z}" | tee -a ${out}; f_CLEANUP_FILES ;done; fi
if [ $option_enum5 = "2" ] && [ -f $tempdir/http ]; then
if [[ $(cat $tempdir/http | wc -w) -gt 0 ]]; then
curl -s https://api.hackertarget.com/whatweb/?q=${x}${api_key_ht} > $tempdir/ww.txt
f_PAGE "${x}" | tee -a ${out}; fi; fi
if [ $option_enum4 = "1" ] ; then
f_certINFO "${x}" | tee -a ${out}; fi; else
if [ $option_type = "1" ] && [ $option_enum1 = "3" ] ; then
f_VHOSTS "${a}" | tee -a ${out}; else
f_hostDEFAULT "${x}" | tee -a ${out}; fi; f_CLEANUP_FILES; fi; done; fi
echo -e "\n"; f_removeDir ; f_Long ; f_targetCONNECT; f_Menu
;;
l|lan)
f_makeNewDir ; out="$tempdir/lan"; domain_enum="false"; bl_check="false"
f_Long | tee -a ${out}; echo -e "[+] LOCAL NETWORKS | $(date)" | tee -a ${out}; f_Long | tee -a ${out}; echo '' | tee -a ${out}
f_IFLIST | tee -a ${out}
f_Long | tee -a ${out}; echo -e "PUBLIC IP ADDRESSES" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' | tee -a ${out}
for nic4 in $(ip -4 addr show | grep -s 'state UP' | cut -d ':' -f 2 | sed 's/^ *//'); do
echo -e "\n\nPublic IPv4:         $(curl -s -m 5 --interface $nic4 https://api.ipify.org?format=json | jq -r '.ip')  ($nic4)"; done > $tempdir/pub4
cat $tempdir/pub4 | tee -a ${out}
for nic6 in $(ip -6 addr show | grep -s 'state UP' | cut -d ':' -f 2 | sed 's/^ *//'); do
publicv6=$(curl -s -m 5 --interface $nic6 https://api64.ipify.org?format=json | jq -r '.ip?' | sed '/null/d')
if [ -n "$publicv6" ]; then
echo -e "\n\nPublic IPv6:         $publicv6  ($nic6)"; echo $publicv6 >> $tempdir/pub6; fi; done | tee -a ${out}; echo '' | tee -a ${out}
f_Long; f_optionsLAN ; echo -e -n "\n    ${B}?${D}   " ; read option_lan
if ! [ $option_lan = "b" ] ; then
if [ $option_lan = "1" ] || [ $option_lan = "6" ]; then
echo ''; f_Long ; echo -e "\n${B}IPV6 NETWORK INTERFACES$\n"; ip -6 addr show | grep -s 'state UP' | cut -d ':' -f 2 | sed 's/^ *//'; echo -e "${D}"
echo -e "\n${B}Settings > ${G2}IPv6 Multicasts${D} > Network Interface ${D}\n"
echo -e "${B}[1]${D} Set specific network interface"
echo -e "${R}[0]${D} Send multicasts from all available interfaces"
echo -e -n "\n${B}  ? ${D}  " ; read option_nic6
if [ $option_nic6 = "1" ]; then
echo -e -n "\n${B}Set  >  ${D}Network Interface -e.g. eth0  ${B}>>${D}  " ; read iface6
if_nmap6="-e $iface6"; echo "$iface6" | sed 's/,/\n/g' | tr -d ' ' > $tempdir/iflist6; else
if_nmap6=''; ip -6 addr show | grep -s 'state UP' | cut -d ':' -f 2 | sed 's/^ *//' > $tempdir/iflist6; fi; fi
if [ $option_lan = "2" ] || [ $option_lan = "3" ] ; then
echo ''; f_Long ; echo -e "\n${B}Settings > ${G2}IPv4 & Ethernet Broadcasts${D} > Network Interface ${D}\n"
echo -e "${B}[1]${D} Set specific network interface"
echo -e "${R}[0]${D} Send broad- / multicasts from all available interfaces"
echo -e -n "\n${B}  ? ${D}  " ; read option_nic4
if [ $option_nic4 = "1" ]; then
echo -e -n "\n${B}Set  >  ${D}Network Interface -e.g. eth0  ${B}>>${D}  " ; read iface4
echo "$iface4" | sed 's/,/\n/g' | tr -d ' ' > $tempdir/iflist4; else
ip -4 addr show | grep -s 'state UP' | cut -d ':' -f 2 | sed 's/^ *//' > $tempdir/iflist4; fi; fi
if [ $option_lan = "1" ] ; then
if [ $report = "true" ]; then
echo ''; f_Long; echo -e -n "\n${B}Output > ${G2}OUTPUT - FILE NAME ${B}>>${D}  " ; read filename
out="${outdir}/$filename.txt"; else
out="$tempdir/output_lan"; fi
cat $tempdir/lan > ${out}; f_Long | tee -a ${out}; echo -e "\nGetting DHCP Config Information ...\n"
dhcp_info=$(sudo ${PATH_nmap} --script broadcast-dhcp-discover 2>/dev/null | grep '|' | tr -d '|_' | sed 's/^ *//' | sed '/Interface:/{x;p;x;}' |
sed '/Subnet Mask/G' | sed '/Message Type:/G' | sed '/NTP Servers:/G' | sed '/broadcast-dhcp-discover:/d' | sed 's/^Response/\n\nRespnse/g')
if [ -n "$dhcp_info" ]; then
echo -e "DHCP-DISCOVER" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' | tee -a ${out}
echo -e "$dhcp_info\n" | tee -a ${out}; echo "$dhcp_info" | grep -E "^Router:" | awk '{print $NF}' | tr -d ' ' > $tempdir/routers; fi
if [ -f $tempdir/iflist6 ]; then
f_DUMP_ROUTER_DHCP_6 | tee -a ${out}; fi
echo ''; f_Long; echo -e "\n${B}Options  > ${G2}IPv4 Routing Info\n"
echo -e "${B}[1]${D} Send RIP2 Discover Broadcast"
echo -e "${B}[2]${D} Send OSPF2 Discover Broadcast"
echo -e "${B} [3]${D} BOTH" ; echo -e "${R} [0]${D} SKIP"
echo -e -n "\n${B}  ? ${D}  " ; read option_route
if [ $option_route = "1" ] || [ $option_route = "3" ] ; then
echo ''  | tee -a ${out}; f_Long  | tee -a ${out}
sudo ${PATH_nmap} --script broadcast-rip-discover 2> /dev/null | grep -E "\||\|_" | sed 's/^|_//g' | sed 's/^|//g' |
sed 's/broadcast-rip-discover:/\nBROADCAST - RIP-Discover\n________________________\n\n/g' > $tempdir/rip
cat $tempdir/rip | tee -a ${out}; sed 's/^ *//' $tempdir/rip | grep -E "0\.0\.\0\.0" | awk '{print $1}' >> $tempdir/routers
echo '' | tee -a ${out}; fi
if [ $option_route = "2" ] || [ $option_route = "3" ] ; then
sudo ${PATH_nmap} --script=broadcast-ospf2-discover 2> /dev/null | grep -E "\||\|_" | sed 's/^|_//g' | sed 's/^|//g' |
sed 's/broadcast-ospf2-discover:/\nBROADCAST - OSPF2-Discover\n__________________________\n\n/g'; fi
if [ -f $tempdir/routers ]; then
f_Long | tee -a ${out}; echo -e "\nTrying to get WAN IPv4 Addresses for discovered routers via NAT port mapping protocol..." | tee -a ${out}
for r in $(cat $tempdir/routers | sort -uV); do
sudo nmap -sU -p 5351 --script=nat-pmp-info $r 2> /dev/null > $tempdir/nat-pmp.txt
f_NMAP_OUT2 "$tempdir/nat-pmp.txt"; done | tee -a ${out}; fi
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo "DNS-SERVICE-DISCOERY, UPNP-INFO, PPPOE-DISCOVERY" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' | tee -a ${out}
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo "[+] BROADCAST | DNS SERVICE DISCOVERY" | tee -a ${out}; f_Long | tee -a ${out}
sudo ${PATH_nmap} --script=broadcast-dns-service-discovery 2> /dev/null | grep -E "\||\|_" | sed 's/^|_//g' | sed 's/^|//g' |
sed 's/broadcast-dns-service-discovery:/\n\nBROADCAST - DNS-Service-Discovery\n_________________________________\n\n/g' | tee -a ${out}
sudo ${PATH_nmap} --script=broadcast-upnp-info 2> /dev/null | grep -E "\||\|_" | sed 's/^|_//g' | sed 's/^|//g' |
sed 's/broadcast-upnp-info:/\n\nBROADCAST - UPNP-INFO\n_____________________\n\n/g'  | tee -a ${out}
sudo ${PATH_nmap} --script=broadcast-ppoe-discover 2> /dev/null | grep -E "\||\|_" | sed 's/^|_//g' | sed 's/^|//g' |
sed 's/broadcast-pppoe-discover:/\n\nBROADCAST - PPOE-Discover\n_________________________\n\n/g' | tee -a ${out}
echo ''; f_Long; echo -e "\n${B}Options  > ${G2}Host Discovery\n"
echo -e "${B}[1]${D} Send ARP broadcast to discover active network hosts"
echo -e "${B}[2]${D} Run Nmap port- & OS-/service version scan (incl. ARP broadcast & SCADA/IoT device discovery)"
echo -e "${B}[3]${D} BOTH"; echo -e "${R} [0]${D} SKIP"; echo -e -n "\n${B}  ? ${D}  " ; read option_hosts2
if ! [ $option_hosts2 = "0" ]; then
echo -e -n "\n${G2}Target ${B}>  [1]${D} Set target network  ${B}| [2]${D} Read from list ${B}?${D}  " ; read option_target
if [ $option_target = "2" ]; then
echo -e -n "\n${B}Target > ${G2}PATH TO FILE  ${B}>>${D}  " ; read input ; target="-iL ${input}"; else
echo -e -n "\n${G2}Target ${B} > ${G2} LOCAL IPV4 NETWORK (CIDR)  ${B}>>${D}  " ; read target; fi
if [ $option_hosts2 = "1" ] || [ $option_hosts2 = "3" ] ; then
echo -e "\n\nARP Broadcast\n_____________\n\n" | tee -a ${out}
sudo nmap -R -sP $targets >> $tempdir/arp; f_ARP | tee -a ${out}; fi
if [ $option_hosts2 = "2" ] || [ $option_hosts2 = "3" ] ; then
declare -a nmap_array=(); nmap_array+=(-sV -sS -sU --version-intensity 4 -O --osscan-limit)
echo -e "\nOptions > Nmap > ${G2}Target Ports\n"
echo -e "${B} [1]${D} Network & SCADA services:\n"; echo "$ports_lan" | fmt -s -w 60
echo -e "\n${B} [2]${D} Custom port list"; echo -e -n "\n${B}  ?${D}  " ; read portChoice
if [ $portChoice = "2" ] ; then
echo -e -n "\n${B}Ports  > ${D} e.g. T:22,U:53,T:80  ${B}>>${D}  " ; read ports; else
ports="$ports_lan"; fi
echo -e "\n${B}Options > ${G2}Nmap ${B}> ${G2} Vulnerability Scan\n"
echo -e "${B} [1]${D} Run Nmap vulnerability scan (script category 'safe')"
echo -e "${B} [2]${D} Run Nmap vulnerability scan (script categoryies 'safe' & 'intrusive')"
echo -e "${R} [0]${D} SKIP vulnerability scanning"; echo -e -n "\n${B}  ? ${D}  " ; read option_vulners
if [ $option_vulners = "1" ]; then
scripts="$nse_lan,$nse_lan_vulners_safe"; script_args=''
elif [ $option_vulners = "2" ]; then
scripts="$nse_lan,$nse_lan_vulners_safe,$nse_lan_vulners_intrusive"; else
scripts="$nse_lan"; script_args=''; fi
echo ''; sudo ${PATH_nmap} ${nmap_array[@]} -p ${ports} --open --script ${scripts} $target 2> /dev/null > $tempdir/nmap.txt
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo -e "[+] $scan_targets  |  NMAP SCAN (IPV4)" | tee -a ${out}
f_NMAP_OUT "$tempdir/nmap.txt" | tee -a ${out}; fi; fi; fi
if [ $option_lan = "2" ] ; then
out="${outdir}/BROADCASTS.ARP.txt"; cat $tempdir/lan > ${out}
echo -e -n "\n${B}Target  > ${G2}Network (CIDR)  ${B}>>${D}  " ; read target
echo '' | tee -a ${out} ; f_Long | tee -a ${out}
for if4 in $(cat $tempdir/iflist4 | sort -uV); do
echo -e "\n\nARP Broadcast\n_____________\n\n"; echo -e "Interface: $if4"; echo -e "Network:   $target"
sudo nmap -e $if4 -R -sP $target 2> /dev/null > $tempdir/arp; f_ARP ; done | tee -a ${out}; fi
if [ $option_lan = "3" ] ; then
for if4 in $(cat $tempdir/iflist4 | sort -uV); do
sudo ${PATH_nmap} -e $if4 --script broadcast-dhcp-discover 2>/dev/null | grep '|' | tr -d '|_' | sed 's/^ *//' | sed '/Interface:/{x;p;x;}' |
sed '/Subnet Mask/G' | sed '/Message Type:/G' | sed '/NTP Servers:/G' |
sed 's/broadcast-dhcp-discover:/\n\nDHCP Discover\n_____________\n/g'; done | tee -a ${out}; fi
if [ $option_lan = "4" ] ; then
echo ''; f_Long; out="${outdir}/ROUTERS_NAT_PMP.txt"; cat $tempdir/lan > ${out}
echo -e -n "\n${G2}Target ${B}>  [1]${D} Set router IP ${B}| [2]${D} Read from list ${B}?${D}  " ; read option_target
if [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target > ${G2}PATH TO FILE  ${B}>>${D}  " ; read input ; target="-iL ${input}"; else
echo -e -n "\n${G2}Target ${B} > ${G2} ROUTER IP ADDRESS  ${B}>>${D}  " ; read target; fi
sudo nmap -sU -p 5351 --script=nat-pmp-info $target 2> /dev/null > $tempdir/nat-pmp.txt
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo "[+] $r | NAT PMP INFO" | tee -a ${out}; f_NMAP_OUT2 "$tempdir/nat-pmp.txt"; fi
if [ $option_lan = "5" ] ; then
echo -e -n "\n${B}Target  > ${G2}Network (CIDR)  ${B}>>${D}  " ; read target
target_id=$(echo $target | cut -d '/' -f 1)
out="${outdir}/NMAP_LAN.$target_id.txt"; cat $tempdir/lan > ${out}
declare -a nmap_array=(); declare -a port_array=(); nmap_array+=(-sV -sS -sU --version-intensity 4 -O --osscan-limit)
echo -e "\nOptions > Nmap > ${G2}Target Ports\n"
echo -e "${B} [1]${D} Network & SCADA services:\n"; echo "$ports_lan" | fmt -s -w 60
echo -e "\n${B} [2]${D} Custom port list"; echo -e -n "\n${B}  ?${D}  " ; read portChoice
if [ $portChoice = "2" ] ; then
echo -e -n "\n${B}Ports  > ${D} e.g. T:22,U:53,T:80  ${B}>>${D}  " ; read ports; else
ports="$ports_lan"; fi
echo -e "\n${B}Options > ${G2}Nmap ${B}> ${G2} Vulnerability Scan\n"
echo -e "${B} [1]${D} Run Nmap vulnerability scan (script category 'safe')"
echo -e "${B} [2]${D} Run Nmap vulnerability scan (script categoryies 'safe' & 'intrusive')"
echo -e "${R} [0]${D} SKIP vulnerability scanning"; echo -e -n "\n${B}  ? ${D}  " ; read option_vulners
if [ $option_vulners = "1" ]; then
scripts="$nse_lan,$nse_lan_vulners_safe"; script_args=''
elif [ $option_vulners = "2" ]; then
scripts="$nse_lan,$nse_lan_vulners_safe,$nse_lan_vulners_intrusive"; else
scripts="$nse_lan"; script_args=''; fi
echo ''; sudo ${PATH_nmap} ${nmap_array[@]} -p ${ports} --open --script ${scripts} $target 2> /dev/null > $tempdir/nmap.txt
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo -e "[+] $scan_targets  |  NMAP SCAN (IPV4)" | tee -a ${out}
f_NMAP_OUT "$tempdir/nmap.txt" | tee -a ${out}; fi
if [ $option_lan = "6" ] ; then
out="${outdir}/ATK6.ROUTER_DHCP6.txt"; cat $tempdir/lan > ${out}; echo '' | tee -a ${out}; f_Long | tee -a ${out}
echo "[+] DUMP DHCP6 - & ROUTER CONFIGS" | tee -a ${out}; f_DUMP_ROUTER_DHCP_6 | tee -a ${out}; fi
fi; echo -e "\n" ; f_removeDir; f_Long; f_Menu
;;
m|mtu) echo ''; f_Long; f_optionsMTU ;;
#************** NETWORK OPTIONS *******************
n|net|nets|networks|prefix|prefixes|pfx|banners|pingsweep|rdns)
f_makeNewDir ; f_Long ; target_type="net" ; domain_enum="false"; out="$tempdir/n"
f_optionsNET ; echo -e -n "\n${B}    ?${D}   " ; read option_enum
if ! [ $option_enum = "b" ] ; then
if [ $option_enum = "3" ] ; then
echo -e "\n${B}Options > ${G2}Type ${B}>\n"
echo -e "${B} [1]${D} IPv4 Network(s)" ; echo -e "${B} [2]${D} IPv6 Network(s)"
echo -e -n "\n${B}  ?${D}   "  ; read option_type ; fi
if [ $option_enum = "1" ] ; then
option_detail="1"; fi
if [ $option_enum =  "2" ] ; then
set_output="false"; option_netdetails3="0"; option_netdetails4="0"
echo -e "\n${B}Options > ${G2}DETAILS I\n" ; echo -e "${B} [1]${D} Network Contact Details"
echo -e "${B} [2]${D} Related networks, geographic distribution, assignments"
echo -e "${B} [3]${D} BOTH" ; echo -e "${R} [0]${D} SKIP" ; echo -e -n "\n${B}  ? ${D}  " ; read option_netdetails1
if [ $option_netdetails1 = "1" ] || [ $option_netdetails1 = "3" ] ; then
option_detail="2" ; else
option_detail="3" ; fi
echo -e "\n${B}Options > ${G2}DETAILS II${B} Whois-Address Space Consistency / Rev. DNS Lookup Zones\n"
echo -e "${B} [1]${D} Show subnets & Address Space Details"; echo -e "${B} [2]${D} List Rev. DNS Lookup Zones (RIPE only)"
echo -e "${B} [3]${D} BOTH" ; echo -e "${R} [0]${D} SKIP"; echo -e -n "\n${B}  ? ${D}  " ; read option_netdetails2; fi
if [ $option_enum =  "3" ] ; then
set_output="false"; option_netdetails2="3"; echo -e "\n${B}Options > ${G2}WHOIS CONTACTS\n"; echo -e "${B} [1]${D} Whois Contact Details"
echo -e "${B} [2]${D} Org & admin-c Summary"; echo -e -n "\n${B}  ? ${D}  " ; read option_custom
if [ $option_custom = "1" ] ; then
option_netdetails1="3"; option_detail="2"; else
option_netdetails1="2"; option_detail="3"; fi
if [ $option_type = "1" ]; then
option_netdetails3="1"; option_netdetails4="1"; dns_servers='' ; option_source="1"; else
option_netdetails3="0"; option_netdetails4="0"; fi; fi
if [ $option_enum =  "5" ] ; then
if [ $option_connect = "0" ] ; then
option_source="3" ; option_ip6="n"; else
f_OPTIONSnetRDNS; echo -e -n "\n${B}  ?${D}  " ; read option_source
if [ $option_source = "2" ] ; then
echo -e -n "\n${G2}NAME SERVER(S)${D} - e.g. 9.9.9.9,anycast.censurfridns.dk  ${B} >>${D}   " ; read input
nssrv=$(echo $input | tr -d ' ')
dns_servers="--dns-servers $nssrv" ; fi ; echo '' ; f_Long
echo -e -n "${B}Option  >${D} Look up ${B}IPv6 Addresses${D} for IPv4 PTR records? ${B} [y] | [n]  ?${D}  " ; read option_ip6; fi; fi
if [ $option_enum =  "6" ] ; then
if [ $option_connect = "0" ] ; then
echo -e "\nPlease enable target-connect mode\n"; else
echo -e -n "\n${B}Target > ${G2}IPv6 NETWORK  ${B}>>${D}  " ; read target
net_ip=$(echo $target | cut -d '/' -f 1); out="${outdir}/REV_DNS.${net_ip}.txt"
if [[ ${net_ip} =~ $REGEX_IP4 ]] ; then
echo -e "\nNo support for IPv4\n"; else
f_getRIR "${target}"
if [ $rir = "ripe" ]; then
f_Long ; echo "REVERSE DNS ZONE" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
f_DELEGATION "${target}"; fi
echo -e -n "\n\n${G2}NAME SERVER  ${B}>>${D}  " ; read target_ns
echo -e -n "\n${B}Option > [1] ${D} UDP  ${B} | [2] ${D} TCP  ${B}?${D}  " ; read input_protocol
if [ $input_protocol = "2" ] ; then
protocol="-t" ; else
protocol="" ; fi
echo '' | tee -a ${out} ; f_Long | tee -a ${out}; echo "[+]  $target  | REVERSE DNS | $(date)" | tee -a ${out}
f_Long | tee -a ${out}; echo '' | tee -a ${out}
sudo ${PATH_rdns6} ${protocol} ${target_ns} ${target} | tee -a ${out}; fi; fi; fi
if ! [ $option_enum =  "6" ] ; then
echo -e -n "\n${G2}Target${B}  > [1]${D} Single target network ${B}| [2]${D} Target list ${B}?${D}  " ; read option_target
if [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target  > ${G2}PATH TO FILE  ${B}>>${D}   " ; read input
nets="${input}" ; else
echo -e -n "\n${B}Target  > ${G2}Network (CIDR)  ${B}>>${D}   " ; read input
echo "$input" > $tempdir/nets.list ; nets="$tempdir/nets.list" ; fi; fi
if [ $option_enum =  "4" ] ; then
if [ $report = "true" ]; then
echo -e -n "\n${B}Option > ${D}Set Custom Name for Output File ${B}[y] | [n]  ?${D}  " ; read option_filename
if [ $option_filename = "y" ] ; then
echo -e -n "\n${B}Output > ${G2}OUTPUT - FILE NAME ${B}>>${D}  " ; read filename
out="${outdir}/$filename.txt" ; else
out="${outdir}/ADDR_SPACE_ENUM.txt" ; fi; fi
echo -e -n "\n${B}Options > ${D}Filter results ${B}[y] | [n]  ?${D}  " ; read option_filter
if [ $option_filter = "y" ] ; then
echo -e -n "\n${B}Filter  > ${D}Single Searchterm or csv - e.g. access,backbone,service  ${B}>>${D}  " ; read filter
echo "$filter" | tr -d ' ' | sed 's/,/\n/g' | tr -d ' ' > $tempdir/filters; fi
echo '' | tee -a ${out}; f_Long | tee -a ${out}
echo -e "[+] PREFIX ADDRESS SPACE / SUBNET SEARCH | $(date)" | tee -a ${out}
f_Long | tee -a ${out}
if [ $option_filter = "y" ] ; then
echo -e "\nSearching for ...\n" | tee -a ${out} ; cat $tempdir/filters | tee -a ${out}
echo -e "\nwithin\n" | tee -a ${out} ; cat $nets | tee -a ${out}; else
echo -e "\nSearching within ...\n" | tee -a ${out} ; cat $nets | tee -a ${out}; fi
echo '' | tee -a ${out}
for x in $(cat "$nets") ; do
net_ip=$(echo $x | cut -d '/' -f 1 | tr -d ' ')
if [[ ${x} =~ ":" ]] ; then
option_type="2"
elif [[ ${net_ip} =~ $REGEX_IP4 ]] ; then
option_type="1" ; fi
f_Long | tee -a ${out}; f_addressSPACE "${x}" | tee -a ${out} ; done; fi
if [ $option_enum = "8" ] ; then
if [ $option_connect = "0" ]; then
echo -e "\nPlease enable target-connect mode\n"; else
declare -a psweep_array=() ; echo -e -n "\n${B}Option  > ${D}Run Nmap with root priviliges ${B}[y] | [n]  ?${D}  " ; read option_root
echo -e "\n${B}Options > ${G2}PING SWEEP\n"; echo -e "${B} [1]${D} Use Nmap Defaults"
echo -e "${B} [2]${D} Customize host discovery options"; echo -e -n "\n${B}  ? ${D}  " ; read option_pingsweep
if [ $option_pingsweep = "2" ] ; then
if [ $option_root = "y" ] ; then
echo -e "\n${B}Options > ${G2}PING${B} > PROTOCOLS${B} > ${G2}ICMP${D}\n"
echo -e "\n(to provoke an ICMP 'protocol unreachable' response select the IP PROTOCOL PING Option further below)\n"
echo -e "${B} [1]${D} ICMP ECHO"
echo -e "${B} [2]${D} ICMP TIMESTAMP"; echo -e "${B} [3]${D} BOTH" ; echo -e "${R} [0]${D} SKIP"
echo -e -n "\n${B}  ? ${D}  " ; read option_icmp
if ! [ $option_icmp = "0" ] ; then
if [ $option_icmp = "1" ] ; then
echo -e "ICMP ECHO REQUEST\n|" >> $tempdir/ping_config
psweep_array+=(-PE)
elif [ $option_icmp = "2" ] ; then
psweep_array+=(-PP); echo -e "ICMP TIMESTAMP REQUEST\n|" >> $tempdir/ping_config; else
echo -e "\nICMP - TYPES: ECHO & TIMESTAMP REQUESTS\n|" >> $tempdir/ping_config; psweep_array+=(-PE -PP) ; fi; fi; fi
echo -e "\n${B}Options > ${G2}PING${B} > PROTOCOLS${B} > ${G2}TCP\n"
echo -e "${B} [1]${D} TCP SYN" ; echo -e "${B} [2]${D} TCP ACK"
echo -e "${B} [3]${D} BOTH" ; echo -e "${R} [0]${D} SKIP"
echo -e -n "\n${B}  ? ${D}  " ; read option_tcp
if ! [ $option_tcp = "0" ] ; then
if [ $option_tcp = "3" ] ; then
echo -e -n "\n${B}Ports   > ${G2} TCP SYN ${B}> - e.g. 25,80,135  ${B}>>${D} " ; read target_ports
echo -e "TCP SYN ($target_ports)\n|" >> $tempdir/ping_config
psweep_array+=(-PS${target_ports})
echo -e -n "\n${B}Ports   > ${G2} TCP ACK ${B}> - e.g. 25,80,135  ${B}>>${D} " ; read target_ports
echo -e "TCP ACK ($target_ports)\n|" >> $tempdir/ping_config
psweep_array+=(-PA${target_ports}) ; else
echo -e -n "\n${B}Ports   > ${D}- e.g. 25,80,135  ${B}>>${D} " ; read target_ports
if [ $option_tcp = "1" ] ; then
echo -e "TCP SYN ($target_ports)\n|" >> $tempdir/ping_config
psweep_array+=(-PS${target_ports}) ; else
echo -e "TCP ACK ($target_ports)\n |" >> $tempdir/ping_config
psweep_array+=(-PA${target_ports}) ; fi ; fi; fi
if [ $option_root = "y" ] ; then
echo -e "\n${B}Options > ${G2}PING${B} > PROTOCOLS${B} > ${G2}IP PROTOCOL SCAN\n"
echo -e "${B} [1]${D} IP Protocol Scan (sends multiple ICMP, IGMP & IP-in-IP packets)"
echo -e "${R} [0]${D} SKIP"; echo -e -n "\n${B}  ? ${D}  " ; read option_PO
if [ $option_PO = "1" ] ; then
echo -e "IP PROTOCOL SCAN (ICMP, IGMP, IP-in-IP)\n|" >> $tempdir/ping_config
psweep_array+=(-PO); fi
echo -e "\n${B}Options > ${G2}PING${B} > PROTOCOLS${B} > ${G2}SCT & UDP\n"; echo -e "${B} [1]${D} SCT (Socket Connect)"
echo -e "${B} [2]${D} UDP"; echo -e "${B} [3]${D} BOTH" ; echo -e "${R} [0]${D} SKIP"; echo -e -n "\n${B}  ? ${D}  " ; read option_udp
if ! [ $option_udp = "0" ] ; then
if [ $option_udp = "3" ] ; then
echo -e -n "\n${B}Ports   > ${G2} SCT ${B}> - e.g. 25,80,135  ${B}>>${D} " ; read target_ports
psweep_array+=(-PY${target_ports})
echo -e "SOCKET CONNECT ($target_ports)\n|" >> $tempdir/ping_config
echo -e -n "\n${B}Ports   > ${G2} UDP ${B}> - e.g. 25,80,135  ${B}>>${D} " ; read target_ports
echo -e "UDP ($target_ports)\n|" >> $tempdir/ping_config
psweep_array+=(-PU${target_ports}) ; else
echo -e -n "\n${B}Ports   > ${D}- e.g. 25,80,135  ${B}>>${D} " ; read target_ports
if [ $option_udp = "1" ] ; then
echo -e "SOCKET CONNECT ($target_ports)\n|" >> $tempdir/ping_config
psweep_array+=(-PY${target_ports}) ; else
echo -e "UDP ($target_ports)\n|" >> $tempdir/ping_config
psweep_array+=(-PU${target_ports}) ; fi; fi; fi; fi; fi; fi; fi
if [ $option_enum = "9" ] ; then
if [ $option_connect = "0" ] ; then
option_source="1" ; else
echo -e "\n${B}Options > IPv4 Nets > ${G2}Service Banners${B}\n"; echo -e "${B} [1] ${G2}API${B}  >${D}  hackertarget.com IP API"
echo -e "${B} [2] ${G2}NMAP${B} >${D}  Version Scan & Host Discovery (Ping)"l echo -e "${B} [3] ${G2}NMAP${B} >${D}  Version Scan, NO Ping"
echo -e -n "\n${B}  ?${D}  " ; read option_source
if ! [ $option_source = "1" ] ; then
declare -a nmap_array=(); declare -a port_array=(); nmap_array+=(-sV -sS -sU --version-intensity 3 --open)
if [ $option_source = "3" ] ; then
nmap_array+=(-Pn) ; fi
echo -e "\n\n${B}Options > ${G2}Target Ports\n"
echo -e "${B} [1]${D}"; echo "$nmap_top15" | fmt -s -w 60
echo -e "${B} [2]${D}\nCustom Port List"; echo -e -n "\n${B}  ?${D}  " ; read portChoice
if [ $portChoice = "1" ] ; then
port_array+=(-p ${nmap_top15}) ; else
echo -e -n "\n${B}Ports   > ${D} e.g. 636,989-995  ${B}>>${D}  " ; read ports
port_array+=(-p ${ports}); fi; fi; fi; fi
if ! [ $option_enum = "4" ] && ! [ $option_enum = "6" ]; then
for x in $(cat $nets) ; do
net_ip=$(echo $x | cut -d '/' -f 1)
if ! [ $option_enum = "3" ] ; then
if [[ ${x} =~ ":" ]] ; then
option_type="2"
elif [[ ${net_ip} =~ $REGEX_IP4 ]] ; then
option_type="1" ; fi ; fi
if [ $option_enum = "1" ] ; then
option_detail="1"; option_netdetails1="0"; option_netdetails2="0"; option_netdetails3="0"; option_netdetails4="0"
out="${outdir}/NETWORKS.txt" ; f_whoisNET "${x}" | tee -a ${out} ; fi
if [ $option_enum = "2" ] ; then
out="${outdir}/NET_ENUM.${net_ip}.txt"; f_whoisNET "${x}" | tee -a ${out}; fi
if [ $option_enum = "3" ] ; then
out="${outdir}/NET_REPORT.${net_ip}.${file_date}.txt"; f_whoisNET "${x}" | tee -a ${out}
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo -e "\nDATE:     $(date)\n" | tee -a ${out}
if [ $option_type = "1" ]; then
echo -e "\nSOURCES:  DNS lookup, hackertarget.com IP API, RIPEstat Data API, whois.$rir.net\n" | tee -a ${out}; else
echo -e "\nSOURCES:  DNS lookup, RIPEstat Data API, whois.$rir.net\n" | tee -a ${out}; fi
echo -e "          port scanning: false\n" | tee -a ${out} ; fi
if [ $option_enum =  "5" ] && [ $option_type = "1" ] ; then
option_netdetails3="0"; f_NET_HEADER "${x}" | tee -a ${out}; f_NETrDNS "${x}" | tee -a ${out}; fi
if [ $option_enum = "7" ] ; then
out="${outdir}/VHOSTS.${net_ip}.txt"
f_NET_HEADER "${x}" | tee -a ${out}; echo -e "*\n $x VHosts\n" | tee -a ${out}; f_RevIP "${x}" | tee -a ${out}; fi
if [ $option_enum = "8" ] ; then
out="${outdir}/PINGSWEEP.${net_ip}.${file_date}.txt"; f_NET_HEADER "${x}" | tee -a ${out}
cat $tempdir/ping_config | sed '$d' | tr '[:space:]' ' ' | sed 's/^ *//' | tee -a ${out}; echo '' | tee -a ${out}
f_Long | tee -a ${out}; echo -e "\n* $x  PING SWEEP" | tee -a ${out}
if [ $option_root = "y" ] ; then
sudo ${PATH_nmap} ${x} -sn ${psweep_array[@]} -oA ${out} > $tempdir/pingsweep.txt ; else
${PATH_nmap} ${x} -sn -R ${psweep_array[@]} -oA ${out} > $tempdir/pingsweep.txt ; fi
grep -E "Nmap scan report|Host is|rDNS" $tempdir/pingsweep.txt  | sed '/scan report/i \_______________________________________________\n' |
sed 's/Nmap scan report for/*/g' | sed 's/Host is/  Host is/g' | tee -a ${out} ; fi
if [ $option_enum = "9" ] ; then
out="${outdir}/BANNERS.${net_ip}.txt" ; f_NET_HEADER "${x}" | tee -a ${out}
if [ $option_source = "1" ]  ; then
f_BANNERS "${x}" | tee -a ${out} ; else
echo '' | tee -a ${out}; sudo ${PATH_nmap} ${nmap_array[@]} -oA ${out}/${filename} ${port_array[@]} ${scripts} ${target} > $tempdir/nmap.txt
f_NMAP_OUT "$tempdir/nmap.txt" | tee -a ${out} ; fi ; fi ; f_CLEANUP_FILES_NET; done; fi ; fi
echo -e "\n" ; f_removeDir; f_Long; f_Menu
;;
p|ports|portscan|nmap) echo '' ; f_Long; f_options_P ;;
t|trace|traceroute|rpki) echo '' ; f_Long; f_options_T ;;
w|who|whois) echo '' ; f_Long; f_optionsWHOIS ;;
#************** WEB SERVER OPTIONS *******************
web|webserver|webservers|website|ssl|tls|www)
f_makeNewDir; f_Long; file_date=$(date +"%b.%d.%Y"); domain_enum="false"; option_detail="1"; blocklists="$blocklists_host"; cert_dump="true"
f_optionsWWW; echo -e -n "\n${B}    ?${D}  "  ; read option_www
if ! [ $option_www = "b" ] ; then
if ! [ $option_www = "3" ] ; then
target_type="web"; fi
if ! [ $option_connect = "0" ] ; then
option_source="1" ; error_code=6; declare -a ping_array=()
echo -e "\n${B}Option > ${G2}curl ${B}> ${G2} User Agent\n"
echo -e "${B} [1]${D} default" ; echo -e "${B} [2]${D} $ua_moz" ; echo -e -n "\n${B}  ? ${D}  " ; read option_ua
if [ $option_ua = "2" ] ; then
curl_ua="-A $ua_moz" ; else
curl_ua="" ; fi
if [ $option_www = "1" ] || [ $option_www = "2" ] ; then
if [ -n "$PATH_testssl" ]; then
option_sslscan="2"; else
option_sslscan="1"; fi; fi
if [ $option_www = "2" ] || [ $option_www = "3" ] ; then
declare -a nmap_array=(); declare -a port_array=()
echo ''; f_Long; echo -e "${B}Option  > ${G2} Raw Socket Priviliges (root-/sudo-users only)${D}\n"
echo -e "Required for\n"; echo -e "Running MTR Traceoute via TCP (default: Tracepath via ICMP)"
echo -e "Nmap Version-, OS- & CVE- Detection"
echo -e -n "\n${G2}Run Applications with elevated priviliges ${B}[y] | [n]  ?${D}  " ; read option_root
if [ $option_root = "y" ] ; then
nmap_array+=(-sV -O --osscan-limit -Pn -R --resolve-all --open); else
nmap_array+=(-sT -Pn -R --resolve-all --open); fi; fi
if [ $option_www = "3" ] ; then
if [ $option_root = "y" ] ; then
echo -e "\n${B}Options > ${G2} Path MTU, Jitter, Packet Loss, Page Loading-, RT- & SSL Handshake Times${D}\n"
echo -e "${B}[1]${D} Run server response- & connectivity tests"
echo -e "${B}[2]${D} Run server response- & connectivity tests, but SKIP MTR"; else
echo -e "\n${B}Options > ${G2} Packet Loss, Page Loading-, RT- & SSL Handshake Times${D}\n"
echo -e "${B}[1]${D} Run server response- & connectivity tests"
echo -e "${B}[2]${D} Run server response- & connectivity tests, but SKIP Tracepath"; fi
echo -e "${R}[0]${D} SKIP"
echo -e -n "\n${B}  ?${D}  " ; read connect_check
if ! [ $connect_check = "0" ]; then
request_times="1"; option_ping="1"; option_sslscan="2"; handshake_details="true"; path_mtu="true"
if [ $connect_check = "1" ]; then
option_trace="y"; ping_array+=(-c 2); else
option_trace="n"; ping_array+=(-c 4); fi; else
request_times="0"; option_ping="0"; option_trace="0"; fi
echo -e "\n${B} Options > Website / Server Security I > ${G2} SSL Configs & Vulnerability Check\n"
echo -e "${B}[1]${D} Run SSL check"
echo -e "${R}[0]${D} SKIP SSL TESTING (show SSL summary only)"
echo -e -n "\n${B}  ?${D}  " ; read sec1
if [ $sec1 = "0" ]; then
option_testSSL="0"; client_sim="false"
if [ $connect_check = "0" ]; then
handshake_details="false"; option_sslscan="0"; fi; else
option_testSSL="3"; echo -e "\n${B}Options > ${G2} SSL\n"
echo -e "${B} [1]${D} Run client simulation tests (Tool: testssl.sh)"
if [ $connect_check = "0" ]; then
echo -e "${B} [2]${D} Show SSL handshake details"; echo -e "${B} [3]${D} BOTH"; fi
echo -e "${R} [0]${D} SKIP" ; echo -e -n "\n${B}  ? ${D}  "; read ssl_details
if [ $ssl_details = "1" ]; then
client_sim="true"
if [ $connect_check = "0" ]; then
handshake_details="false"; fi
elif [ $ssl_details = "2" ]; then
handshake_details="true"; client_sim="false"
elif [ $ssl_details = "3" ]; then
handshake_details="true"; client_sim="true"; else
client_sim="false"
if [ $connect_check = "0" ]; then
handshake_details="false"; fi; fi; fi
echo -e "\n${B} Options > Website / Server Security II > ${G2} Target Information\n"
echo -e "${B} [1]${D} Whois, Geolocation, BGP, Website Scraping"
echo -e "${B} [2]${D} Virtual Hosts  ${B}IPv4${D} (hackertarget.com API)"
echo -e "${B} [3]${D} BOTH"; echo -e "${R} [0]${D} SKIP"; echo -e -n "\n${B}  ?${D}  " ; read sec2
if [ $sec2 = "1" ] || [ $sec2 = "3" ]; then
page_details="true"; target_type="other"
echo -e -n "\n${B}Options >${D} WhatWeb ${B}> [1]${D} Local App ${B}| [2]${D} hackertarget.com API  ${B}| ${R}[0]${D} SKIP  ${B}?${D}  "
read ww_source
if [ $ww_source = "1" ] || [ $ww_source = "2" ] ; then
ww="true" ; else
ww="false" ; fi ; else
page_details="false"; target_type="web"; ww="false"; fi
echo -e "\n\n${B} Options > Website / Server Security III > ${G2} Nmap Scan\n"
echo -e "${B} [1]${D} Safe Mode - (Uses Nmap Script from category 'safe' only)"
echo -e "${B} [2]${D} Intrusive Mode - FAST (using 'safe' & 'intrusive' skripts, skipping time consuming script scans)"
echo -e "${B} [3]${D} Intrusive Mode - SLOW"; echo -e "${R} [0]${D} SKIP"; echo -e -n "\n${B}  ?${D}  " ; read sec3
if ! [ $sec3 = "0" ]; then
if [ $sec3 = "2" ]; then
if [ $option_root = "y" ] ; then
scripts="--script=${nse_web1},vulners"; script_args="--script-args http-methods.test-all"; else 
scripts="--script=${nse_web1}"; script_args="--script-args http-methods.test-all"; fi 
elif [ $sec3 = "3" ]; then
if [ $option_root = "y" ] ; then
scripts="--script=${nse_web1_root},${nse_web2}"; script_args="--script-args http-methods.test-all"; else
scripts="--script=${nse_web1},${nse_web2}"; script_args="--script-args http-methods.test-all"; fi; else
if [ $option_root = "y" ] ; then
scripts="--script=${nse_basic},${nse_web_safe_root}"; script_args=''; else 
scripts="--script=${nse_basic},${nse_web_safe}"; script_args=''; fi; fi 
echo -e "\n\n${B}Options > ${G2}Nmap Target Ports\n"
echo -e "${B} [1]${D} $ports_web1"; echo -e "${B} [2]${D} $ports_web2"; echo -e "${B} [2]${D} $ports_web3"
echo -e "${B} [4]${D} customize ports" ; echo -e -n "\n${B}  ? ${D}  " ; read option_ports
if [ $option_ports = "1" ] ; then
ports="$ports_web1"
elif [ $option_ports = "2" ] ; then
ports="$ports_web2"; else
echo -e -n "\n${B}Set     > Ports  ${D}- e.g. 636,989-995  ${B}>>${D} " ; read ports
ports=(${add_ports}) ; fi; fi
echo -e "\n\n${B} Options > ${B} Website / Server Security IV > ${G2}WFUZZ \n"
echo -e "${B} [1]${D} Check robots.txt" ; echo -e "${B} [2]${D} Server Directories Bruteforcing"
echo -e "${B} [3]${D} BOTH" ; echo -e "${R} [0]${D} SKIP" ; echo -e -n "\n${B}  ? ${D}  " ; read sec4; fi
if [ $option_www = "6" ] ; then
echo -e "\n\n${B}Options > ${G2} SSL\n"; echo -e "${B} [1]${D} SSL quick- / bulk info"
echo -e "${B} [2]${D} SSL file dump (quiet)"; echo -e "${B} [3]${D} BOTH" ; echo -e -n "\n${B}  ? ${D}  "; read ssl_bulk
if [ $ssl_bulk = "1" ]; then
cert_dump="false"; else
cert_dump="true"; fi
if [ $ssl_bulk = "1" ] || [ $ssl_bulk = "3" ] ; then
out="${outdir}/SSL_QUICK_BULK.txt"; f_Long >> ${out}; echo "[+]  SSL QUICK- / BULK CHECK  |  $(date)" >> ${out}; fi; fi; fi
echo ''; f_Long; echo -e -n "\n${B}Target  > [1]${D}  Set Target ${B}| [2]${D}  Target List  ${B}?${D}  " ; read option_target
if [ $option_target = "1" ] ; then
echo -e -n "\n${B}Target  > ${G2}HOSTNAME  ${B}>>${D}  " ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list" ; else
echo -e -n "\n${B}Target > ${G2}PATH TO FILE  ${B}>>${D} " ; read input
targets="${input}" ; fi
for x in $(cat "$targets") ; do
if [ $option_connect = "0" ] ; then
out="${outdir}/HEADERS.${x}.txt"; f_HEADERS "${x}" | tee -a ${outdir}/HEADERS.${x}.txt; else
declare -a st_array=() ; st_array+=(-sLkv); declare -a curl_array=() ; curl_array+=(-sLkv)
if [ $option_www = "1" ] ; then
ww="false"; option_testSSL="2"; page_details="false"; handshake_details="false"; request_times="1"; bl_check="true"; path_mtu="false"
quiet_dump="false"; option_root="n"; sec1="0"; sec2="0"; sec3="0"; sec4="0"; target_type="web"; option_ping="1"; ping_array+=(-c 4); option_trace="0"
out="${outdir}/WEBSERV_HealthCheck.${x}.${file_date}.txt"
elif [ $option_www = "2" ] ; then
out="${outdir}/WEBSERV_Health_Vulners_Check.${x}.${file_date}.txt"
target_type="other"; page_details="true"; cert_dump="true"; quiet_dump="false"; option_ping="1"; option_trace="0"; sec2="1"; sec3="2"; sec4="0"; ww="false"
request_times="1"; client_sim="false"; option_testSSL="3"; handshake_details="false"; bl_check="true"; path_mtu="true"; ping_array+=(-c 4)
script_args="--script-args http-methods.test-all"; ports="$ports_web2"
if [ $option_root = "y" ] ; then
scripts="--script=${nse_web1_root}"; else 
scripts="--script=${nse_web1}"; fi
elif [ $option_www = "3" ] ; then
out="${outdir}/WEBSERV.${x}.${file_date}.txt"; bl_check="true"; quiet_dump="false"
elif [ $option_www = "4" ] ; then
bl_check="false"; target_type="web"; page_details="true"; ww="false"; ssl_details="false"; option_testSSL="0" option_sslscan="0"
handshake_details="0"; sec1="0"; sec2="0"; path_mtu="false"; request_times="0"; out="${outdir}/WEBSITE.${x}.txt"
elif [ $option_www = "5" ] ; then
out="${outdir}/HEADERS.${x}.txt"; fi
curl -s -f -L -k ${x} > /dev/null
if [ $? = ${error_code} ]; then
echo -e "\n${R} $x WEBSITE CONNECTION: FAILURE${D}\n\n"
echo -e "\n $x WEBSITE CONNECTION: FAILURE\n" >> ${out} ; else
f_CLEANUP_FILES; if [ $option_www = "6" ] ; then
if [ $ssl_bulk = "2" ] ; then
quiet_dump="true" ; f_certINFO "${x}" ; quiet_dump="false"; else
echo ''; quiet_dump="false"; target_type="web_short"; option_testSSL="0"; option_sslscan="0"; f_certINFO "${x}" | tee -a ${out}; echo ''; fi
elif [ $option_www = "5" ] ; then
curl -sILk --max-time 3 ${x} > $tempdir/headers; f_HEADERS "${x}" | tee ${out}; else
f_writeOUT "${x}" ; f_HEADERS "${x}" > ${outdir}/HEADERS.${x}.txt; f_www_test_HEADER | tee -a ${out}
target4=$(host -t a $x | grep -w 'has address' | awk '{print $NF}' | tr -d ' ')
target6=$(host -t aaaa $x | grep -w 'has IPv6' | awk '{print $NF}' | tr -d ' ')
echo "$target4" | tee $tempdir/ips_all > $tempdir/ip4.list; echo "$target6" | tee -a $tempdir/ips_all > $tempdir/ip6.list
eff_url=$(grep 'URL:' $tempdir/response | rev | cut -d ' ' -f 1 | rev)
target_host=$(echo $eff_url | sed 's/http:\/\///' | sed 's/https:\/\///' | cut -d '/' -f 1)
if ! [ "$x" = "$target_host" ] ; then
target_host4=$(host -t a $target_host | grep -w -i "has address" | rev | cut -d ' ' -f 1 | rev | sort -V)
target_host6=$(host -t aaaa $target_host | grep -w -i "has IPv6 address" | rev | cut -d ' ' -f 1 | rev | sort -V)
echo "$target_host4" | tee -a $tempdir/ips_all >> $tempdir/ip4.list; echo "$target_host6" | tee -a $tempdir/ips_all >> $tempdir/ip6.list; fi
echo '' | tee -a ${out}; f_PAGE "${x}" | tee -a ${out}
if [ $option_www = "4" ] ; then
cat ${outdir}/LINK_DUMP.${x}.txt | tee -a ${out}
cat ${outdir}/HEADERS.${x}.txt | tee -a ${out}; else
if [ $option_root = "y" ] && [ $path_mtu = "true" ]; then
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo "PATH-MTU" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' | tee -a ${out}
sudo ${PATH_nmap} -sS -Pn -p 80 --open --resolve-all --script path-mtu $x 2> /dev/null > $tempdir/pmtu; f_PATH_MTU | tee -a ${out}
if [ -n "$target6" ]; then
sudo ${PATH_nmap} -6 -sS -Pn -p 80 --open --resolve-all --script path-mtu $x  2> /dev/null > $tempdir/pmtu; f_PATH_MTU | tee -a ${out}; fi; fi
if [ $sec2 = "2" ] || [ $sec2 = "0" ]; then
if [ $option_trace = "y" ] && [ $option_root = "y" ] ; then
declare -a mtr_array=() ; mtr_array+=(--tcp -P 80 -c 5 -n -z); mtr_info="AUTO, TCP:80, PACKETS: 5"
for a in $target4; do
f_MTR "${a}"; done | tee -a ${out}
if [ -n "$target6" ]; then
mtr_info="IPV6, TCP:80, PACKETS: 5"
declare -a mtr_array=() ; mtr_array+=(-6 --tcp -P 80 -c 5 -n -z)
for z in $target6; do
f_MTR "${z}"; done | tee -a ${out}; fi; fi
if [ $option_trace = "y" ] && [ $option_root = "n" ] ; then
path_args="-4 -b -m 25"; for a in $target4; do
f_TRACEPATH "${a}"; done | tee -a ${out}
if [ -n "$target6" ]; then
path_args="-6 -b -m 25"; for z in $target6; do
f_TRACEPATH "${z}"; done | tee -a ${out}; fi; fi; fi
if [ $ww = "true" ] ; then
if [ $ww_source = "1" ] ; then
${PATH_whatweb} --no-errors --color=never ${x} > $tempdir/ww.txt
elif [ $ww_source = "2" ] ; then
curl -s https://api.hackertarget.com/whatweb/?q=${x}${api_key_ht} > $tempdir/ww.txt ; fi ; fi
if ! [ $sec3 = "0" ]; then
echo -e "\nRunning Nmap Scan ...\n"
if [ -n "$target4" ]; then
option_ipv="1"; f_RUN_NMAP "${x}" | tee -a ${out}; fi
if [ -n "$target6" ]; then
option_ipv="2"; f_RUN_NMAP "${x}" | tee -a ${out}; fi; fi
echo '' | tee -a ${out}; declare -a st_array=(); st_array+=(-s4Lkv); declare -a htping_array=(); htping_array+=(-c 3); target="$x"
for a in $target4 ; do
echo ''; f_serverINSTANCE "${a}" ; done | tee -a ${out}
if [ -n "$target6" ] ; then
declare -a st_array=() ; st_array+=(-sLkv); htping_array+=(-6 -c 3)
for z in $target6 ; do
echo ''; f_serverINSTANCE "${z}" ; done | tee -a ${out}; fi
if [ -n "$target_host4" ]; then
if ! [ "$target4" = "$target_host4" ] ; then
declare -a st_array=() ; st_array+=(-s4Lkv); target_type="web" ; target="${target_host}"
for a in $target_host4 ; do
f_serverINSTANCE "${a}" ;done | tee -a ${out} ; fi
if [ -n "$target_host6" ]; then
declare -a st_array=() ; st_array+=(-sLkv); htping_array+=(-6 -c 3)
for z in $target_host6 ; do
f_serverINSTANCE "${z}" ; done | tee -a ${out}; fi; fi
hashes_outfile="WEBSITE_HASHES_$x.$file_date.txt"; f_HASHES_OUT "${x}" >> ${outdir}/$hashes_outfile
if [[ $(cat $tempdir/ips_all | sort -uV | wc -w) -gt 1 ]]; then
echo -e "\n" | tee -a ${out}; f_Long | tee -a ${out}; echo "WEBSITE HASHES" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' | tee -a ${out}
cat $tempdir/hashes_temp | tee -a ${out}; fi
if [ $sec2 = "1" ] || [ $sec2 = "3" ]; then
cat $tempdir/page.html > $outdir/SOURCE.${x}.html
if [[ $(cat $tempdir/ips_all | sort -u | wc -w) -lt 3 ]]; then
if [ $option_trace = "y" ]; then
declare -a mtr_array=(); mtr_array+=(--tcp -P 80 -c 5 -n -z); mtr_info="AUTO, TCP:80, PACKETS: 5"; path_args="-4 -b -m 25"; fi
for a in $target4; do
f_BOGON "${a}"
if [ $bogon = "TRUE" ] ; then
echo -e "\nBOGON Address detected [$a]\n" | tee -a ${out}; else
f_WEB "${a}" | tee -a ${out};fi; done
if [ -n "$target6" ]; then
if [ $option_trace = "y" ]; then
declare -a mtr_array=() ; mtr_array+=(-6 --tcp -P 80 -c 5 -n -z); mtr_info="IPV6, TCP:80, PACKETS: 5"; path_args="-6 -b -m 25"; fi
for z in $target6; do
f_WEB "${z}"; done | tee -a ${out}; fi; fi; fi
f_certINFO "${x}" | tee -a ${out}
if ! [ "$x" = "$target_host" ] ; then
serial_domain=$(echo | timeout 3 openssl s_client -connect ${x}:443 2>/dev/null | openssl x509 -noout -nocert -serial)
serial_target_host=$(echo | timeout 3 openssl s_client -connect ${target_host}:443 2>/dev/null | openssl x509 -noout -nocert -serial)
if ! [ "$serial_domain" = "$serial_target_host" ] ; then
echo '' | tee -a ${out}; f_certINFO "${target_host}" | tee -a ${out}; fi; fi
if [ $sec2 = "1" ] || [ $sec2 = "3" ]; then
if [[ $(cat $tempdir/ips_all | sort -uV | wc -w) -gt 1 ]]; then
if [ $option_trace = "y" ]; then
declare -a mtr_array=(); mtr_array+=(-4 --tcp -P 80 -c 5 -n -z); mtr_info="AUTO, TCP:80, PACKETS: 5"; path_args="-4 -b -m 25"; fi
for a in $target4; do
f_BOGON "${a}"
if [ $bogon = "TRUE" ] ; then
echo -e "\nBOGON Address detected [$a]\n" | tee -a ${out}; else
f_WEB "${a}" | tee -a ${out};fi; done
if [ -n "$target6" ]; then
if [ $option_trace = "y" ]; then
declare -a mtr_array=() ; mtr_array+=(-6 --tcp -P 80 -c 5 -n -z); mtr_info="IPV6, TCP:80, PACKETS: 5"; path_args="-6 -b -m 25"; fi
for z in $target6; do
f_WEB "${z}"; done | tee -a ${out}; fi; fi; fi
if [ $sec2 = "2" ] || [ $sec2 = "3" ]; then
for a in $target4; do
f_VHOSTS "${a}"; done | tee -a ${out}; fi
if ! [ $sec2 = "0" ] || ! [ $sec3 = "0" ]; then
cat $tempdir/LINKS.${x}.txt | tee -a ${out}
echo '' | tee -a ${out}; f_htmlCOMMENTS "${x}" | tee -a ${out}
if ! [ "$x" = "$target_host" ] ; then
f_htmlCOMMENTS "${target_host}" | tee -a ${out}; fi; fi
if [ $sec4 = "1" ] || [ $sec4 = "3" ] ; then
if [ -n "$PATH_wfuzz" ] ; then
echo '' | tee -a ${out} ; f_Long | tee -a ${out} ; echo -e "[+] $target_host | robots.txt [WFUZZ] " | tee -a ${out} ; f_Long | tee -a ${out}
echo '' | tee -a ${out} ; ${PATH_wfuzz} --script=robots -z list,robots.txt -f $tempdir/fuzz $target_host/FUZZ ; echo ''
cat $tempdir/fuzz >> ${out} ; rm $tempdir/fuzz ; else
echo "Please install WFUZZ"; fi; fi
if [ $sec4 = "2" ] || [ $sec4 = "3" ] ; then
if [ -n "$PATH_wfuzz" ] ; then
echo '' | tee -a ${out} ; f_Long | tee -a ${out} ; echo -e "[+] $target_host | SERVER DIRECTORIES | [WFUZZ]" | tee -a ${out} ; f_Long | tee -a ${out}
wfuzz -w ${wordl_wfuzz1} --hc 404,403 -f $tempdir/fuzz $target_host/FUZZ ; echo ''
cat $tempdir/fuzz >> ${out} ; rm $tempdir/fuzz ; else
echo "Please install WFUZZ"; fi; fi
if ! [ $option_www = "1" ] && [[ $(cat $tempdir/ips_all | wc -w) -gt 1 ]]; then
cat ${outdir}/HEADERS.${x}.txt | tee -a ${out}; fi
if [ $handshake_details = "true" ]; then
cat $tempdir/writeout.${target}.txt | tee -a ${out}; fi
if ! [ $option_www = "1" ] && [[ $(cat $tempdir/ips_all | wc -w) -lt 2 ]]; then
cat ${outdir}/HEADERS.${x}.txt | tee -a ${out}; fi; fi; fi; fi; fi; done
fi; echo ''; f_removeDir; f_Long; f_Menu
;;
#************** AFRINIC, APNIC & RIPE INVERSE & REVERSE SEARCHES (NETWORKS, ORGANISATIONS, CONTACTS) *******************
1)
f_makeNewDir ; f_Long ; target_type="other" ; out="$tempdir/out11.txt" ; option_detail="1"; domain_enum="false"; orgs=''; orgs_other=''
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
echo -e "\nRegular & inverse Lookups can be combined in file input"; f_Long
echo -e -n "\n${G2}Target  ${B}> [1]${D} Set target ${B}| [2]${D} Read from file  ${B}?${D}  " ; read option_target
if [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target  > ${G2}PATH TO FILE ${D}e.g. ./objects.list  ${B}>>${D}   " ; read input
targets="${input}" ; else
echo -e -n "\n${B}Target  > ${G2}SEARCH TERM  ${B}>>${D} " ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list" ; fi
if [ $option_target = "2" ] && [ $report = "true" ] ; then
echo -e -n "\n${B}Output  > ${G2}OUTPUT - FILE NAME  ${B}>>${D}  " ; read filename ; fi
headl="$tempdir/headline"
echo -e "\n${R}Warning: ${D} Excessive searches for non-abuse contact details are considered abusive."
echo -e "\n${B}Options > ${G2}PoC Details\n"
echo -e "${B} [1]${D} Do not Search for Personal Data"
echo -e "${B} [2]${D} Look up Full Contact Details"
echo -e "${B} [3]${D} Retrieve contact details once for every object, but do not search for personal data during inverse Lookups"
echo -e -n "\n${B}   ?${D}  " ; read option_poc
echo '' > ${headl}; f_Long | tee -a ${headl}; echo -e "WHOIS | OBJECT & INVERSE SEARCHES  [$regserver]  ($file_date)" | tee -a ${headl}
f_Long | tee -a ${headl}; echo -e "\nSearching...\n" | tee -a ${headl} ; cat $targets | tee -a ${headl}
for x in $(cat $targets) ; do
if  [[ ${x} =~ ";" ]] ; then
iSearch="true" ; query_type=$(echo "$x" | cut -d ';' -f 1) ; obj=$(echo "$x" | cut -d ';' -f 2)
if [ $query_type = "org" ] ; then
echo "$obj" | tr -d ' ' >> $tempdir/orgs1.list
elif [ $query_type = "admin-c" ] ; then
echo "$obj" | tr -d ' ' | tee -a $tempdir/objects.list >> $tempdir/admins1_raw
elif [ $query_type = "origin" ] ; then
echo "$obj" | tr -d ' ' | tee -a $tempdir/objects.list >> $tempdir/asns.list; else
echo "$obj" >> $tempdir/objects.list; fi
if [ $option_target = "1" ] ; then
filename=$(echo $x | cut -d ';' -f 2- | tr -d ' ') ; fi ; else
iSearch="false"
if [ $option_target = "1" ] ; then
filename=$(echo $x | cut -d '/' -f 1 | tr -d ' ') ; fi ; fi
if [ $iSearch = "true" ] ; then
if [ $option_poc = "2" ] ; then
whois -h ${regserver} -- "-B -i ${query_type} ${obj}"  >> $tempdir/whois_temp ; else
whois -h ${regserver} -- "--no-personal -i ${query_type} ${obj}" | tr -d '*' | sed 's/^ *//' >> $tempdir/whois_temp ; fi
f_whoisFORMAT >> $tempdir/who1.txt; else
if [ $option_poc = "2" ] ; then
whois -h ${regserver} -- "-B ${x}" >> $tempdir/whois_temp ; else
whois -h ${regserver} -- "--no-personal ${x}"  | tr -d '*' | sed 's/^ *//' >> $tempdir/whois_temp ; fi
f_whoisFORMAT >> $tempdir/who1.txt ; fi ; done
if [ $iSearch = "true" ] ; then
for o in $(cat $tempdir/objects.list | sort -uV) ; do
if [ $option_poc = "3" ] ; then
whois -h ${regserver} -- "-B ${o}" | sed 's/% Information related/Information related/' | sed 's/% Abuse contact/Abuse contact/' |
sed '/%/d' |  sed '/mnt-ref:/d' | sed '/source:/d' | sed '/remarks:/d' |  sed '/fax:/d' | sed '/^#/d' | sed '/^%/d' | sed '/^$/d' |
sed '/Information related/i \_______________________________________________________________________________\n' > $tempdir/who2_raw.txt
cat $tempdir/who2_raw.txt | sed '/Abuse contact/G' | sed 's/Abuse contact for .*. is/\[@\]: /'  | sed 's/Information related to /* /' | tr -d "\'"  |
sed '/organisation:/{x;p;x;}' | sed '/person:/{x;p;x;}' | sed '/role:/{x;p;x;}' | sed '/route:/{x;p;x;}' | sed '/route6:/{x;p;x;}' |
sed '/inetnum:/{x;p;x;}' | sed '/inet6num/{x;p;x;}' | sed '/mntner:/{x;p;x;}' | sed '/as-set:/{x;p;x;}' | sed '/aut-num:/{x;p;x;}' |
sed '/domain:/{x;p;x;}' >> $tempdir/who2.txt; else
f_Long >> $tempdir/obj; echo -e "$o\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' >> $tempdir/obj
whois -h ${regserver} -- "-F -r ${o}" | tr -d '*' | sed 's/^ *//' > $tempdir/obj_temp
obj_phone=$(grep -E -a "^ph:" $tempdir/obj_temp | cut -d ':' -f 2- | sed 's/^ *//' | sort -u | tr '[:space:]' ' '; echo '')
obj_mail=$(grep -s -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/obj_temp | sort -u | tr '[:space:]' ' '; echo '')
obj_address=$(grep -E -a "^ad:|^\+" $tempdir/obj_temp | cut -d ':' -f 2- | sed 's/^+ //' | sed 's/^ *//' | tr '[:space:]' ' '; echo '')
grep -E -a "^mt:|^ro:|^pn:|^de:" $tempdir/obj_temp | cut -d ':' -f 2- | sed 's/^ *//' >> $tempdir/obj
if [ -n "$obj_address" ]; then
echo -e "\n$obj_address\n" >> $tempdir/obj; fi
if [ -n "$obj_phone" ]; then
echo -e "\n$obj_phone\n" >> $tempdir/obj; fi
if [ -n "$obj_mail" ]; then
echo -e "\n$obj_mail\n" >> $tempdir/obj; fi
grep -E "^ac:|^mb:" $tempdir/obj_temp | sed 's/ac: /admin-c;/g' | sed 's/mb: /mnt-by;/g' >> $tempdir/obj; echo '' >> $tempdir/obj; fi; done
if [ $option_poc = "3" ]; then
cat $tempdir/who2.txt > $tempdir/full_output.txt; fi; fi; cat $tempdir/who1.txt >> $tempdir/full_output.txt
grep -E "^aut-num:|^an:|^origin:|^or:" $tempdir/full_output.txt | cut -d ':' -f 2- | sed 's/^ *//' >> $tempdir/asns.list
asns=$(cat $tempdir/asns.list | tr -d ' ' | sort -ug)
netnames=$(grep -E -i "^netname:|^na:|^net-name:" $tempdir/full_output.txt | cut -d ':' -f 2- | sed 's/^ *//' | sort -uV)
grep -s -E "^organisation:|^org:|^oa:|^og:"  $tempdir/full_output.txt | cut -d ':' -f 2- | sed 's/^ *//' | sort -uV > $tempdir/orgs2.list
if [[ $(cat $targets) =~ ";" ]] ; then
if [ -f $tempdir/orgs1.list ] && [ -f $tempdir/orgs2.list ]; then
orgs=$(sort -uV $tempdir/orgs1.list)
orgs_other=$(diff --suppress-common-lines --ignore-all-space $tempdir/orgs1.list $tempdir/orgs2.list | grep '>' | cut -d ' ' -f 2);else
if [ -f $tempdir/orgs2.list ]; then
orgs_other=$(cat $tempdir/orgs2.list); fi; fi; else
orgs_other=''; fi
if ! [ $option_poc = "3" ] && [[ $(cat $targets) =~ ";" ]] ; then
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo "[+] QUERIED OBJECTS  (EXCLUDING ORGS & ASNs)" | tee -a ${out}; cat $tempdir/obj | tee -a ${out}; fi
if [ -n "$asns" ] || [ -n "$orgs" ]; then
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo "[+] AUTONOMOUS SYSTEMS & QUERIED ORGANISATIONS" | tee -a ${out}; f_Long | tee -a ${out}
if [ -n "$asns" ] ; then
echo -e "\n* ASNs\n" | tee -a ${out}; echo "$asns" | sed 's/AS/AS /g' | tee -a ${out} ; fi
if [ -n "$orgs" ] ; then
echo -e "\n* ORGs (Searchlist)\n" | tee -a ${out} ; echo -e "$orgs" | tee -a ${out}; fi; echo '' | tee -a ${out}
if [ -n "$asns" ] ; then
for a in $(echo "$asns" | sed 's/AS//g') ; do
f_AS_SUMMARY "${a}" ; done | tee -a ${out} ; fi
if [ -n "$orgs" ] ; then
for oid in $orgs; do
whois -h ${regserver} -- "--no-personal $oid" > $tempdir/whois_org
echo ''; f_ORG "$tempdir/whois_org" ; done | tee -a ${out}
for oid in $orgs; do
echo '' ; f_netBLOCKS "${oid}" ; done | tee -a ${out}; fi; fi
if [ -n "$orgs_other" ] ; then
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo -e "[+] RELATED ORGANISATIONS" | tee -a ${out}
f_Long | tee -a ${out}; echo -e "\n* ORGs (related)\n" | tee -a ${out}; echo -e "$orgs_other\n" | tee -a ${out}
for oid in $orgs_other; do
whois -h ${regserver} -- "--no-personal $oid" > $tempdir/whois_org
echo ''; f_ORG "$tempdir/whois_org"; done | tee -a ${out}
for oid in $orgs_other; do
echo '' ; f_netBLOCKS "${oid}"; done | tee -a ${out}; fi
#**** NETWORKS ****
if [[ $(grep -E -a -s -c "^inetnum:|^in:|^inet6num:|^i6:" $tempdir/full_output.txt) -gt "0" ]] ; then
echo '' | tee -a ${out} ; f_Long | tee -a ${out} ; echo -e "[+] NETWORKS" | tee -a ${out}; f_Long | tee -a ${out}
if [[ $(grep -s -E -c "^inet6num:|^i6:" $tempdir/full_output.txt ) -gt "0" ]] ; then
echo -e "\nNetworks (IPv6)\n_________________" | tee -a ${out}
grep -s -E -A 5 "^inet6num:|^i6:" $tempdir/full_output.txt > $tempdir/i6nums1
grep -E "^inet6num:|^i6:" $tempdir/i6nums1 | cut -d ' ' -f 2- | tr -d ' ' | sort -u -V > $tempdir/i6nums2
for i in $(cat $tempdir/i6nums2 | sort -u -V) ; do
grep -s -A 5 -m 1 ${i} $tempdir/i6nums1 | grep -s -E "^inet6num:|^netname:|^country:|^org-name:|^descr:" |
sed '/inet6num/i \nnn' | sed '/inet6num/a \nnn' | sed '/^netname:/a \|' | sed '/^org-name:/a \|' | sed '/^descr:/a \|' |
sed '/^country:/a \|' | sed '$d' | cut -d ' ' -f 2- | sed 's/^ *//' | tr '[:space:]' ' ' | sed 's/nnn/\n\n/g' |
sed '/|/G' | sed 's/^ *//' ; done | tee -a ${out} ; fi
if [[ $(grep -s -E -c "^inetnum:" $tempdir/full_output.txt ) -gt 0 ]] ; then
if [[ $(grep -s -E -c "^inet6num:|^i6:" $tempdir/full_output.txt ) -gt "0" ]] ; then
echo ''; fi; echo -e "\nNetworks (IPv4)\n_________________" | tee -a ${out}
grep -s -E -A 2 "^inetnum:" $tempdir/full_output.txt > $tempdir/inetnums1
grep -s -E "^inetnum:" $tempdir/inetnums1  | cut -d ':' -f 2- | tr -d ' ' | cut -d '-' -f 1 > $tempdir/inetnums2
sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n -u $tempdir/inetnums2 > $tempdir/inetnums_u4
grep -s -w '^inetnum:|^in:' $tempdir/inetnums1  | cut -d ':' -f 2- | tr -d ' ' | cut -d '-' -f 2 >> $tempdir/inetnums2
sort -t . -k 1,1n -k 2,2n -k 3,3n -u $tempdir/inetnums2 > $tempdir/inetnums_u3
for a in $(cat $tempdir/inetnums_u4) ; do
inum=$(grep -s -m 1 "${a}" $tempdir/inetnums1 | cut -d ':' -f 2- | sed 's/^ *//' | tr -d ' ')
inum_cidr=$(ipcalc ${inum} | sed '/deaggregate/d' | sed '/^$/d' | tr '[:space:]' ' ')
echo -e "\n\n$inum\n" | sed 's/-/ - /' >> $tempdir/netranges.txt
grep -s -m 1 -A 2 "${a}" $tempdir/inetnums1 | tail -2 | sed '/^netname:/a \|' | sed '/^org:/a \|' | sed '/^descr:/a \|' |
sed '/^country:/a \|' | cut -d ':' -f 2- | sed 's/^ *//' | tr '[:space:]' ' ' >> $tempdir/netranges.txt
echo -e "$inum_cidr\n" >> $tempdir/netranges.txt
nrange=$(grep -s -m 1 "${a}" $tempdir/inetnums1 | cut -d ':' -f 2- | tr -d ' ')
ipcalc ${nrange} | sed '/deaggregate/d' | sed '/^$/d' >> $tempdir/cidr ; done
cat $tempdir/netranges.txt | tee -a ${out}; rm $tempdir/netranges.txt; echo '' | tee -a ${out}
if [[ $(cat $tempdir/cidr | wc -w) -gt 2 ]]; then
echo -e "_______________________________________\n"  | tee -a ${out}
cat $tempdir/cidr | tr -d ' '  | sort -t / -k 2,2n | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n -u -V | tr '[:space:]' ' ' | sed 's/ /  /g' |
sed 's/^ *//' | fmt -s -w 40 | tee -a ${out} ; else
echo ''; f_Shortest | tee -a ${out}; cat $tempdir/cidr | tr -d ' '  |
sort -t / -k 2,2n | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n -u -V | tee -a ${out}; fi ; fi; fi
#**** ROUTE OBJECTS ****
route_obj4=$(sed -e '/./{H;$!d;}' -e 'x;/route:/!d' $tempdir/full_output.txt | grep -E "^route:|^origin" | grep -E -B 1 "^origin:" |
sed '/--/d' | sed '/^$/d')
route_obj6=$(sed -e '/./{H;$!d;}' -e 'x;/route6:/!d' $tempdir/full_output.txt | grep -E "^route6:|^origin" | grep -E -B 1 "^origin:" |
sed '/--/d' | sed '/^$/d')
if [ -n "$route_obj4" ] || [ -n "$route_obj6" ] ; then
echo -e "\n" | tee -a ${out}; f_Long | tee -a ${out}; echo "[+] ROUTES" | tee -a ${out}; f_Long | tee -a ${out}; fi
if [ -n "$route_obj6" ] ; then
echo -e "\nRoutes (IPv6)\n_____________" | tee -a ${out}; echo "$route_obj6" | sed 's/as/AS/g' > $tempdir/route_obj6
origin6=$(grep -E "^or:|^origin:" $tempdir/route_obj6 | cut -d ':' -f 2- | sed 's/^ *//' |  tr -d ' ' | sort -u -f -V)
for i in $origin6 ; do
echo -e "\n\n$i\n" | sed 's/AS/AS /g'
grep -E -B 1 "${i}" $tempdir/route_obj6 | sed '/--/d' | sed '/^$/d' | grep -E -v "^origin:" | cut -d ' ' -f 2- |
sed 's/^ *//' | tr -d ' ' | sort -uV ; done | tee -a ${out} ; fi
if [ -n "$route_obj4" ] ; then
if [ -n "$origin6" ]; then
echo -e "\n"; fi
echo -e "\nRoutes (IPv4)\n_____________" | tee -a ${out}; echo "$route_obj4" | sed 's/as/AS/g' > $tempdir/route_obj4
origin4=$(grep -E "^origin:" $tempdir/route_obj4 | cut -d ':' -f 2- | sed 's/^ *//' |  tr -d ' ' | sort -u -f -V)
for o in $origin4 ; do
echo -e "\n\n$o\n" | sed 's/AS/AS /g'; grep -E -B 1 "${o}" $tempdir/route_obj4 | sed '/--/d' | sed '/^$/d' | grep -E -v "^origin:" | cut -d ' ' -f 2- |
sed 's/^ *//' | tr -d ' ' | sort -u -V >> $tempdir/routes4
cat $tempdir/routes4 | tr -d ' '  | sort -t / -k 2,2n | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n -u -V
rm $tempdir/routes4 ; done | tee -a ${out} ; fi
#**** ABUSE CONTACTS / POCs ****
if [ $option_poc = "1" ] ; then
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo -e "[+] ABUSE CONTACTS & ADMIN-C" | tee -a ${out}; f_Long | tee -a ${out}
echo -e "* Abuse Contacts\n" | tee -a ${out}
cat $tempdir/full_output.txt | grep -s -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" | sort -u | tee -a ${out} ; else
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo -e "[+] POINTS OF CONTACT" | tee -a ${out}; f_Long | tee -a ${out}; echo '' | tee -a ${out}
grep -s -E "^role:|^person:" $tempdir/full_output.txt | cut -d ':' -f 2- | sed 's/^ *//' | sort -u | tee -a ${out}; echo '' | tee -a ${out}
grep -s "^nic-hdl:" $tempdir/full_output.txt | cut -d ':' -f 2- | sed 's/^ *//' | sort -u
echo '' | tee -a ${out}; grep -s -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/full_output.txt | sort -u | tee -a ${out}; fi
if [[ $(grep -E -a -s -c "^admin-c:|^ac:" $tempdir/full_output.txt) -gt "0" ]] ; then
echo -e "\n\n* $iregistry Admin Handles\n" | tee -a ${out}
grep -s -E "^admin-c:|^ac:" $tempdir/full_output.txt  | sed 's/ac:/admin-c:/g' | tr ':' ';' | tr -d ' ' > $tempdir/handles.txt
sort -u $tempdir/handles.txt | tee -a ${out}
echo '' | tee -a ${out} ; cut -d ';' -f 2 $tempdir/handles.txt | sed 's/^ *//' | tr -d ' ' | sort -uV > $tempdir/admins2.list; fi
if [ -f $tempdir/admins1_raw ]; then
sort -uV $tempdir/admins1_raw > $tempdir/admins1.list
admins=$(diff --suppress-common-lines --ignore-all-space $tempdir/admins1.list $tempdir/admins2.list | grep '>' | cut -d ' ' -f 2); else
admins=$(cat $tempdir/admins2.list); fi
for ac in $admins ; do
f_Long; f_ADMIN_C "${ac}" ; done | tee -a ${out}
nameservers=$(grep -E "^ns:|^nserver:" $tempdir/who1.txt | cut -d ':' -f 2- | sed 's/^ *//' | sort -uV)
if [ -n "$nameservers" ] ; then
echo '' | tee -a ${out}; f_Long | tee -a ${out} ; echo "[+]  NAME SERVERS  [SOURCE: WHOIS REVERSE DNS DELEGATIONS]" | tee -a ${out}; f_Long | tee -a ${out}
for n in $nameservers; do
echo ''; host $n | sed 's/has address/  has address/g' | sed 's/is an/  is an/g'; echo ''; done | tee -a ${out}; fi
mail_domains=$(grep -s -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/full_output.txt | cut -d '@' -f 2 | sort -u)
if [ -n "$mail_domains" ] ; then
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo "[+] DOMAINS" | tee -a ${out}
for md in $mail_domains ; do
f_Long; echo -e "DOMAIN WHOIS STATUS" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
f_whoisSTATUS "${md}"; addresses_v4=$(dig a +short $md)
echo -e "$md:"
for a in $(echo "$addresses_v4" | sort -uV) ; do
f_hostSHORT "${a}"; done ; done | tee -a ${out}; fi
if [ $option_poc = "3" ] ; then
f_Long | tee -a ${out}; echo "[+] Object Details" | tee -a ${out}
cat $tempdir/who2.txt | tee -a ${out} ; fi
if [ $option_poc = "2" ] ; then
f_Long | tee -a ${out}; echo "[+] OBJECT DETAILS" | tee -a ${out}
cat $tempdir/who1.txt | sed 's/^ *//' | tr -d "\'" | sed '/organisation:/{x;p;x;}' | sed '/person:/{x;p;x;}' |
sed '/role:/{x;p;x;}' | sed '/route:/{x;p;x;}' | sed '/route6:/{x;p;x;}' | sed '/inetnum:/{x;p;x;}' | sed '/inet6num/{x;p;x;}' |
sed '/mntner/{x;p;x;}' | sed '/as-set/{x;p;x;}' | sed '/aut-num:/{x;p;x;}' | sed '/domain:/{x;p;x;}' | tee -a ${out} ; fi
cat $headl >> ${outdir}/WHOIS.${filename}.txt ; cat ${out} >> ${outdir}/WHOIS.${filename}.txt
cat $tempdir/who1.txt >> ${outdir}/WHOIS_full_out.txt ; echo -e "\n" ; f_removeDir; f_Long; f_Menu
;;
#************** ARIN NETWORK, ORGANISATION & CONTACT SEARCH  *******************
2)
f_makeNewDir ; f_Long ; option_detail="4" ; domain_enum="false" ; rir="arin"
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
target_type="net"; f_whoisNET "${x}" | tee -a ${out}
mail_domains=$(grep -E "^AbuseEmail|^OrgAbuseEmail:" $tempdir/whois | grep -E -m1 -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" | cut -d '@' -f 2)
orgid=$(grep -E "^OrgId:" $tempdir/whois | awk '{print $NF}' | head -1 | sed 's/^ *//' | tr -d ' '); f_DNSWhois_STATUS "${mail_domain}" | tee -a ${out}
elif  [[ ${x} =~ $REGEX_DOMAIN ]] || [[ ${x} =~ "@" ]] ; then
target_type="other"; echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo -e "[+]  $orgid | Networks  [source: whois.arin.net]" | tee -a ${out}
f_Long | tee -a ${out}; grep -s -E "^Name:|^Handle:|^Company:|^City:|^Country:|^Updated:|^Phone:|^Email:" $tempdir/whois |
sed 's/Name:/\n\nName:/' | tee -a ${out}
handle=$(grep -E "^Handle:" $tempdir/whois | head -1 | awk '{print $NF}' | sed 's/^ *//' | tr -d ' ')
orgid=$(whois -h whois.arin.net z $handle | grep -E "^OrgId:" | awk '{print $NF}' | sed 's/^ *//' | tr -d ' ') ; else
f_ARIN_ORG "$tempdir/whois" | tee -a ${out} ; orgid=$(grep -E "^OrgId:" $tempdir/whois | awk '{print $NF}' | head -1 | sed 's/^ *//' | tr -d ' ')
mail_domains=$(grep -E "^AbuseEmail|^OrgAbuseEmail:" $tempdir/whois | grep -E -m1 -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" | cut -d '@' -f 2); fi
if [ -n "$mail_domains" ] ; then
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo "[+] Domains" | tee -a ${out}
for md in $mail_domains ; do
f_DNSWhois_STATUS "${md}"
addresses_v4=$(jq -r '.data.forward_nodes' $tempdir/chain.json | tr -d '{",}' | sed '/\[/d' | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
for a in $(echo "$addresses_v4" | sort -uV) ; do
f_Long; echo -e "$a\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; f_hostSHORT "${a}"; done ; done | tee -a ${out}; fi
net_name=$(grep -E "^NetName:" $tempdir/whois | head -1 | awk '{print $NF}' | sed 's/^ *//' | tr -d ' ')
f_netRESOURCES "${net_name}"
if [ -n "$orgid" ] ; then
if [[ ${x} =~ $REGEX_DOMAIN ]] || [[ ${x} =~ "@" ]] ; then
whois -h whois.arin.net o $orgid > $tempdir/arin_org
f_Long | tee -a ${out}; echo "[+]  $orgid" | tee -a ${out}; f_ARIN_ORG "$tempdir/arin_org" | tee -a ${out}; fi
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo -e "[+]  $orgid | Networks  [source: whois.arin.net]" | tee -a ${out}; f_Long | tee -a ${out}
echo '' | tee -a ${out} ; whois -h whois.arin.net n $orgid | grep '('  | tee -a ${out} ; echo '' | tee -a ${out}
f_netBLOCKS "${orgid}" | tee -a ${out}; fi
if ! [[ ${x} =~ $REGEX_DOMAIN ]] || ! [[ ${x} =~ "@" ]] ; then
f_Long | tee -a ${out} ; echo -e "[+] $x Points of Contact" | tee -a ${out}; f_Long | tee -a ${out}; echo '' | tee -a ${out}
whois -h whois.arin.net -- "e + @$mail_domain" | grep -a -E "^Name:|^Handle:|^Company:|^City:|^Country:|^Updated:|^Phone:|^Email:" |
sed 's/Name:/\n\nName:/' | tee -a ${out} ; fi
done ; echo -e "\n" ; f_removeDir; f_Long; f_Menu
;;
#************** pwhois.org NETBLOCK & ORGANISATION SEARCH *******************
3)
f_makeNewDir ; f_Long ; out="${outdir}/Netblocks.txt"
echo -e -n "\n${B}Target > [1]${D} Set target ${B}| [2]${D} Read from file  ${B}?${D}  " ; read option_target
if [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target  > ${D}PATH TO FILE  ${B}>>${D}   " ; read input
targets="${input}" ; else
echo -e -n "\n${B}Target  > ${D}SEARCH TERM ${B}>>${D} " ; read input
echo "$input" > $tempdir/targets.list
targets="$tempdir/targets.list" ; fi
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo "[+] Organisation- & Netblock- Search  [pwhois.org]" | tee -a ${out}; f_Long | tee -a ${out}
for oid in $(cat $targets) ; do
whois -h whois.pwhois.org "registry org-name=${oid}" > $tempdir/pwhois_org
grep -E "^Org-ID:|^Org-Name:|^Country:|^City:|^Register Date:|^NOC-0-Handle:|^NOC-1-Handle:|^Abuse-0-Handle:" $tempdir/pwhois_org |
sed '/RIPE-NCC-HM-MNT/d' | sed '/Org-ID:/{x;p;p;x}'; done | tee -a ${out}
for oid in $(cat $targets) ; do
f_netBLOCKS "${oid}" ; done | tee -a ${out} ; echo ''; f_removeDir; f_Long; f_Menu
;;
#************** pwhois.org BULK LOOKUPS *******************
4)
f_makeNewDir ; f_Long; target_type="other"
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
f_Long | tee -a ${out}; f_whoisTABLE  "${input}" ; cat $tempdir/whois_table.txt | tee -a ${out}; fi; echo ''; f_removeDir; f_Long; f_Menu
;;
#************** NMAP MTU DISCOVERY *******************
m1)
f_makeNewDir ; f_Long ; out="${outdir}/PATH-MTU.${file_date}.txt"
if [ $option_connect = "0" ] ; then
f_targetCONNECT; fi
if ! [ $option_connect = "0" ] ; then
echo -e "\n${B}NMAP Path MTU Discovery (TCP)${D}"
echo -e -n "\n${B}Target  > [1]${D} Set target ${B}| [2]${D} Target list  ${B}?${D}  " ; read option_target
if [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target  > ${D}PATH TO FILE ${B}>>${D}  " ; read input
targets="$input" ; else
echo -e -n "\n${B} Target  >${G2}  IP ADDRESS / HOSTNAME  ${B}>>${D}  " ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list" ; fi
echo -e -n "\n${G2}TARGET PORTS ${D} - e.g. U:53,T:80  (U for UDP; T for TCP)  ${B}>>${D}  " ; read port_input_mtu
ports_mtu=$(echo $port_input_mtu | tr -d ' ')
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo -e "[+]  PATH MTU  [NMAP]  |  $(date)" | tee -a ${out}; f_Long | tee -a ${out}
for t in $(cat $targets | sort -uV) ; do
x=$(echo $t | sed 's/http[s]:\/\///' | cut -d '/' -f 1 | tr -d ' ')
if [[ ${x} =~ ":" ]] ; then
sudo ${PATH_nmap} -6 -sS -sU -Pn -p ${ports_mtu} --open --resolve-all --script path-mtu $x -oG $tempdir/path_mtu6 2> /dev/null >> $tempdir/pmtu
f_PATH_MTU | tee -a ${out}; echo '' | tee -a ${out}
elif [[ ${x} =~ $REGEX_IP4 ]] ; then
sudo ${PATH_nmap} -sS -sU -Pn -p ${ports_mtu} --open --resolve-all --script -oG $tempdir/path_mtu $x 2> /dev/null > $tempdir/pmtu
f_PATH_MTU | tee -a ${out}; echo '' | tee -a ${out}; else
target_4=$(dig a +short $x); target_6=$(dig aaaa +short $x)
if [ -n "$target_4" ]; then
sudo ${PATH_nmap} -sS -sU -Pn -p ${ports_mtu} --open --resolve-all --script -oG $tempdir/path_mtu $x 2> /dev/null > $tempdir/pmtu
f_PATH_MTU | tee -a ${out}; echo '' | tee -a ${out}; fi
if [ -n "$target_6" ]; then
sudo ${PATH_nmap} -sS -sU -Pn -p ${ports_mtu} --open --resolve-all --script -oG $tempdir/path_mtu $x 2> /dev/null > $tempdir/pmtu
f_PATH_MTU | tee -a ${out}; echo '' | tee -a ${out}; fi; fi; echo ''; done; else
f_WARNING; fi ; f_removeDir; f_Long; f_Menu
;;
t1|m2)
#************** TRACEPATH *******************
f_makeNewDir ; f_Long; out="${outdir}/ROUTES_TRACEPATH.${file_date}.txt"
if [ $option_connect = "0" ] ; then
f_targetCONNECT; fi
if ! [ $option_connect = "0" ] ; then
echo -e "\n${B}Options > Tracepath > ${G2} Mode\n"
echo -e "${B} [1]${D}  IPv4"; echo -e "${B} [2]${D}  IPv6" ; echo -e "${B} [3]${D}  Auto (default)"
echo -e -n "\n\n${B}  ?${D}   " ; read IPvChoice
echo -e -n "\n${B}Target  > [1]${D} Set target (hostname, IPv4 ${B}| [2]${D} Target list  ${B}?${D}  " ; read option_target
if [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target  > ${D}PATH TO FILE ${B}>>${D}  " ; read input
targets="$input" ; else
echo -e -n "\n${B}Target  >${G2} TARGET  ${B}>>${D}  " ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list"; fi
echo -e -n "\n${B}Option  >${G2} HOPS ${B}>${D} Max. number of Hops (default:30) ${B}>>${D}  "; read hops
if [ $IPvChoice = "2" ]; then
bl_check="false"; path_args="-6 -b -m $hops"; else
bl_check="true"; blocklists="$blocklists_hop"
if [ $IPvChoice = "1" ] ; then
path_args="-4 -b -m $hops"; else
path_args="-b -m $hops"; fi; fi
echo -e "\n${B}Option  > ${G2} Hop Details${D}\n"
echo -e "${B} [1]${D} Retrieve Geolocation-, Whois-, BGP/RPKI & - IPv4 only - IP Reputation Data"
echo -e "${R} [0]${D} SKIP"; echo -e -n "\n${B}  ? ${D}  " ; read option_hop_details
echo -e -n "\n${G2}Get MAC Addresses for local hops (elevated priviliges required) ${B}[y] | [n]  ?${D}  " ; read option_root
if [ $option_hop_details = "1" ]; then
domain_enum="false"; option_detail="1"; target_type="hop"; out="${outdir}/TRACEPATH_HOP_DETAILS.${file_date}.txt"; else
out="${outdir}/ROUTES_TRACEPATH.${file_date}.txt"; fi
for x in $(cat "$targets") ; do
echo '' | tee -a ${out}; f_TRACEPATH "${x}"; hoplist=$(cut -s -d '(' -f 2 $tempdir/trace | cut -d ')' -f 1 | tr -d ' ')
if [ $option_root = "y" ] && [ -n "$hoplist" ]; then
echo ''; for h in $(echo "$hoplist" | head -3); do
f_BOGON "${h}"
if [ $bogon = "TRUE" ] ; then
f_Long; echo "$h"; f_Long
if [[ ${h} =~ $REGEX_IP4 ]] ; then
sudo nmap -R -sP 2> /dev/null $h | grep -E "scan report|MAC Address" | sed '/Nmap scan report/{x;p;x;G}' | sed 's/Nmap scan report for //g' |
sed '/MAC Address/G'; else
sudo nmap -6 -R -sP 2> /dev/null $h | grep -E "scan report|MAC Address" | sed '/Nmap scan report/{x;p;x;G}' | sed 's/Nmap scan report for //g' |
sed '/MAC Address/G'; fi; fi; done; fi
if [ $option_hop_details = "1" ] && [ -n "$hoplist" ]; then
if [ $IPvChoice = "1" ] ; then
curl -s "https://www.peeringdb.com/api/ixpfx?protocol__in=IPv4" > $tempdir/ix_pfx.json
jq -r '.data[] | .prefix, .ixlan_id' $tempdir/ix_pfx.json > $tempdir/ix_pfx
elif [ $IPvChoice = "2" ]; then
curl -s "https://www.peeringdb.com/api/ixpfx?protocol__in=IPv6" > $tempdir/ix_pfx6.json
jq -r '.data[] | .prefix, .ixlan_id' $tempdir/ix_pfx6.json > $tempdir/ix_pfx; else
curl -s "https://www.peeringdb.com/api/ixpfx?protocol__in=IPv4" > $tempdir/ix_pfx.json
jq -r '.data[] | .prefix, .ixlan_id' $tempdir/ix_pfx.json > $tempdir/ix_pfx
curl -s "https://www.peeringdb.com/api/ixpfx?protocol__in=IPv6" > $tempdir/ix_pfx6.json
jq -r '.data[] | .prefix, .ixlan_id' $tempdir/ix_pfx6.json >> $tempdir/ix_pfx; fi; echo '' | tee -a ${out}
for i in $(echo "$hoplist" | sed '1,1d'); do
f_HOP "${i}"; echo ''; f_CLEANUP_FILES; done
echo ''; f_Long; echo "[+] ASNs"; for a in $(cat $tempdir/asns | sort -ug); do
f_AS_SUMMARY "${a}"; done; rm $tempdir/asns; fi; done | tee -a ${out}; echo '' | tee -a ${out}; else
f_WARNING; fi; echo ''; f_removeDir; f_Long; f_Menu
;;
#************** MTR (local installation) *******************
t2)
f_makeNewDir; f_Long; domain_enum="false"; option_detail="1"; target_type="hop"; declare -a mtr_array=()
if [ $option_connect = "0" ] ; then
f_targetCONNECT; fi
if ! [ $option_connect = "0" ] ; then
echo -e -n "\n${B}Options > ${G2} MTR ${B} > [1]${D} IPV4 MODE  ${B}| [2]${D}  IPV6 MODE ${B}| [3]${D}  AUTO (DEFAULT)  ${B}?${D}  " ; read IPvChoice
if [ $IPvChoice = "2" ] ; then
mtr_array+=(-6 -z -n); mtr_mode="IPV6"; bl_check="false"; else
bl_check="true"; blocklists="$blocklists_hop"; if [ $IPvChoice = "1" ] ; then
mtr_mode="IPV4"; mtr_array+=(-4 -b -z); else
mtr_mode="AUTO"; mtr_array+=(-z); fi; fi
echo -e -n "\n${B}Target  > [1]${D} Set target (hostname, IPv4 ${B}| [2]${D} Target list  ${B}?${D}  " ; read option_target
if [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target  > ${D}PATH TO FILE ${B}>>${D}  " ; read input
targets="$input" ; else
echo -e -n "\n${B}Target  >${G2} TARGET  ${B}>>${D}  " ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list"; fi
echo -e "\n${B}Option  > ${G2} Hop Details${D}\n"
echo -e "${B} [1]${D} Retrieve Geolocation-, Whois-, BGP/RPKI & IP Reputation Data"
echo -e "${R} [0]${D} SKIP"; echo -e -n "\n${B}  ? ${D}  " ; read option_hop_details
if ! [ $option_hop_details = "0" ]; then
domain_enum="false"; option_detail="1"; target_type="hop"; out="${outdir}/MTR_HOP_DETAILS.${file_date}.txt"; else
out="${outdir}/ROUTES_MTR.${file_date}.txt"; fi
echo -e -n "\n${B}Option  > ${G2} Max. hops (default 30): ${B}max hops  >>${D}  " ; read hops
mtr_array+=(-m ${hops})
echo -e -n "\n${B}Option  > ${G2} No of pings (e.g. 5) ${B}>>${D}  " ; read pingcount; mtr_array+=(-c ${pingcount})
echo -e "\n${B}Options >${G2}  Protocols\n"; echo -e "${B} [1]${D} ICMP (Type: Echo)"; echo -e "${B} [2]${D} TCP"
echo -e "${B} [3]${D} UDP"; echo -e "${B} [4]${D} SCTP (Stream Control Transmission Protocol)"; echo -e -n "\n${B}  ? ${D}  " ; read protocol_input
if ! [ $protocol_input = "1" ] ; then
echo -e -n "\n${B}Option  >${G2}  Target Port (e.g. 25)  ${B}>>${D}  " ; read tport
if [ $protocol_input = "2" ] ; then
mtr_array+=(--tcp -P $tport) ; mtr_protocol="TCP:$tport"
elif [ $protocol_input = "3" ] ; then
mtr_array+=(--udp -P $tport); mtr_protocol="UDP:$tport"
elif [ $protocol_input = "4" ] ; then
mtr_array+=(--sct -P $tport); mtr_protocol="SCT:$tport"; fi ; else
mtr_protocol="ICMP"; fi; mtr_info="$mtr_mode, $mtr_protocol, PING COUNT: $pingcount"
for x in $(cat "$targets") ; do
f_MTR "${x}"
if  [ $IPvChoice = "1" ] ; then
hoplist=$(grep -E "[0-9]{1,2}\." $tempdir/mtr.txt | egrep -s -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'); else
hoplist=$(grep -E "[0-9]{1,2}\." $tempdir/mtr.txt | awk '{print $3}') ; fi
if [ -n "$hoplist" ]; then
echo ''; for h in $(echo "$hoplist" | head -3); do
f_BOGON "${h}"; if [ $bogon = "TRUE" ] ; then
f_Long; echo "$h"; f_Long
if [[ ${h} =~ $REGEX_IP4 ]] ; then
sudo nmap -R -sP 2> /dev/null $h | grep -E "scan report|MAC Address" | sed '/Nmap scan report/{x;p;x;G}' | sed 's/Nmap scan report for //g' |
sed '/MAC Address/G'; else
sudo nmap -6 -R -sP 2> /dev/null $h | grep -E "scan report|MAC Address" | sed '/Nmap scan report/{x;p;x;G}' | sed 's/Nmap scan report for //g' |
sed '/MAC Address/G'; fi; fi; done
if ! [ $option_hop_details = "0" ]; then
if [ $IPvChoice = "1" ] ; then
curl -s "https://www.peeringdb.com/api/ixpfx?protocol__in=IPv4" > $tempdir/ix_pfx.json
jq -r '.data[] | .prefix, .ixlan_id' $tempdir/ix_pfx.json > $tempdir/ix_pfx
elif [ $IPvChoice = "2" ]; then
curl -s "https://www.peeringdb.com/api/ixpfx?protocol__in=IPv6" > $tempdir/ix_pfx6.json
jq -r '.data[] | .prefix, .ixlan_id' $tempdir/ix_pfx6.json > $tempdir/ix_pfx; else
curl -s "https://www.peeringdb.com/api/ixpfx?protocol__in=IPv4" > $tempdir/ix_pfx.json
jq -r '.data[] | .prefix, .ixlan_id' $tempdir/ix_pfx.json > $tempdir/ix_pfx
curl -s "https://www.peeringdb.com/api/ixpfx?protocol__in=IPv6" > $tempdir/ix_pfx6.json
jq -r '.data[] | .prefix, .ixlan_id' $tempdir/ix_pfx6.json >> $tempdir/ix_pfx; fi; echo ''
for i in $(echo "$hoplist" | sed '1,1d'); do
f_HOP "${i}"; echo ''; f_CLEANUP_FILES; done
echo ''; f_Long; echo "[+] ASNs"; for a in $(cat $tempdir/asns | sort -ug); do
f_AS_SUMMARY "${a}"; done; rm $tempdir/asns; fi; fi; done | tee -a ${out}; echo '' | tee -a ${out}; else
f_WARNING; fi; echo ''; f_removeDir; f_Long; f_Menu
;;
t3)
#************** MTR (via hackertarget.com IP Tools API) *******************
f_makeNewDir ; f_Long; out="${outdir}/ROUTES_MTR.API.txt"
echo -e -n "\n${G2}MTR (API) ${B}> Target > ${G2}IPV4 ADDRESS / HOSTNAME  ${B}>>${D}  " ; read target
echo -e "\n${B}Option  > ${G2} Hop Details${D}\n"
echo -e "${B} [1]${D} Retrieve Geolocation-, Whois-, BGP/RPKI & - IPv4 only - IP Reputation Data"
echo -e "${R} [0]${D} SKIP"; echo -e -n "\n${B}  ? ${D}  " ; read option_hop_details
if [ $option_hop_details = "1" ]; then
domain_enum="false"; option_detail="1"; target_type="hop"; out="${outdir}/MTR.API_HOP_DETAILS.${file_date}.txt"; else
out="${outdir}/ROUTES_MTR.API.${file_date}.txt"; fi; echo ''; f_MTR_HT "${target}" | tee -a ${out}
hoplist=$(grep -E "[0-9]{1,2}\.\|--" $tempdir/mtr_ht | egrep -s -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' |
sed '/^$/d' | sed '1,1d' | tr -d ' ')
if ! [ $option_hop_details = "0" ] && [ -n "$hoplist" ]; then
domain_enum="false"; target_type="hop"; option_detail="1"; bl_check="true"; blocklists="$blocklists_hop"
curl -s "https://www.peeringdb.com/api/ixpfx?protocol__in=IPv4" > $tempdir/ix_pfx.json
jq -r '.data[] | .prefix, .ixlan_id' $tempdir/ix_pfx.json > $tempdir/ix_pfx; echo '' | tee -a ${out}
for i in $hoplist; do
hop_addr="$i"
if ! [[ ${i} =~ $REGEX_IP4 ]] ; then
a=$(dig @anycast.censurfridns.dk a +short $i | egrep -s -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'); else
a="$i"; fi
if [[ ${a} =~ $REGEX_IP4 ]] ; then
f_HOP "${a}"; echo ''; f_CLEANUP_FILES; fi; done | tee -a ${out}
echo ''; f_Long; echo "[+] ASNs"; for a in $(cat $tempdir/asns | sort -ug); do
f_AS_SUMMARY "${a}"; done | tee -a ${out}; rm $tempdir/asns; echo '' | tee -a ${out}; fi
echo ''; f_removeDir; f_Long; f_Menu
;;
#************** NMAP (script traceroute-geolocation.nse) *******************
t4)
f_makeNewDir; f_Long; domain_enum="false"; option_detail="1"; target_type="hop"; blocklists="$blocklists_hop"; bl_check="true"; declare -a nmap_arr=()
out="${outdir}/ROUTES_NMAP.txt"
if [ $option_connect = "0" ] ; then
f_targetCONNECT; fi
if ! [ $option_connect = "0" ] ; then
echo -e -n "\n${B}Nmap Geo Traceroute > Options > ${G2}MODE ${B} > [1]${D} IPV4 MODE  ${B}| [2]${D}  IPV6 MODE  ${B}?${D}  " ; read IPvChoice
if [ $IPvChoice = "2" ] ; then
nmap_array+=(-6); fi
echo -e "\n${B}Options >${G2}  Protocols\n"; echo -e "${B} [1]${D} ICMP (Type: Echo)"; echo -e "${B} [2]${D} TCP Connect"
echo -e "${B} [3]${D} TCP SYN"; echo -e "${B} [4]${D} TCP ACK"; echo -e "${B} [5]${D} UDP"
echo -e "${B} [6]${D} IP Protocol Scan"; echo -e -n "\n${B}  ? ${D}  " ; read protocol_input
if ! [ $protocol_input = "1" ] ; then
echo -e -n "\n${B}Option  >${G2}  Target Port (e.g. 25)  ${B}>>${D}  " ; read tport
target_port="-p $tport"
if [ $protocol_input = "2" ] ; then
nmap_array+=(-PN -sT)
elif [ $protocol_input = "3" ] ; then
nmap_array+=(-PN -sS)
elif [ $protocol_input = "4" ] ; then
nmap_array+=(-PN -sA)
elif [ $protocol_input = "5" ] ; then
nmap_array+=(-PN -sU)
elif [ $protocol_input = "6" ] ; then
nmap_array+=(-PN -sO); fi; else
nmap_array+=(-sn -Pn); target_port=''; fi
echo -e -n "\n${B}Nmap Geo Traceroute > Options > [1]${D} Set target Host | IP Address  ${B}| [2]${D} Target list  ${B}?${D}  " ; read option_target
if [ $option_target = "1" ] ; then
echo -e -n "\n${B}Target > ${G2} IP ADDRESS / HOSTNAME  ${B}${B}  >>${D}   " ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list"
elif [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target > ${D}PATH TO FILE  ${B}>>${D}  " ; read input
targets="$input"; out="${outdir}/ROUTES_GEOtrace.${file_date}.txt"; fi
echo -e "\n${B}Option  > ${G2} Hop Details${D}\n"
echo -e "${B} [1]${D} Retrieve Geolocation-, Whois-, BGP/RPKI & - IPv4 only - IP Reputation Data"
echo -e "${R} [0]${D} SKIP"; echo -e -n "\n${B}  ? ${D}  " ; read option_hop_details
if [ $option_hop_details = "1" ]; then
out="${outdir}/GEOtrace_HOP_DETAILS.${file_date}.txt"; else
out="${outdir}/ROUTES_GEOtrace.${file_date}.txt"; fi
for t in $(cat "$targets") ; do
x=$(echo $t | sed 's/http[s]:\/\///' | cut -d '/' -f 1 | tr -d ' ')
if [ $option_target = "1" ] ; then
out="$outdir/ROUTES.${x}.txt";fi
sudo ${PATH_nmap} ${nmap_array[@]} ${target_port} --traceroute --script=traceroute-geolocation 2>/dev/null $x > $tempdir/geotrace
echo '' | tee -a ${out} ; f_Long | tee -a ${out} ; echo "[+] NMAP GEO TRACEROUTE | $x" | tee -a ${out} ; f_Long | tee -a ${out}
grep -E -v "Host script results:|traceroute-geolocation:|Starting Nmap|\.\.\.|Nmap done:" $tempdir/geotrace | sed 's/^|_//g' | sed 's/^|//g' | sed 's/^ *//' |
sed '/Nmap scan report for/G' | sed '/Nmap scan report/i \_______________________________________________________________________________\n' |
sed 's/Other addresses for .*. (not scanned):/\nNot scanned: /g' | sed 's/rDNS record for/rDNS:        /g' | sed '/PROTOCOL/G' | sed '/RTT/{x;p;x;G}'
if [ $IPvChoice = "1" ] ; then
hoplist=$(grep -E "^\|" $tempdir/geotrace | egrep -s -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sed '1,1d'); else
hoplist=$(grep -E "^\|" $tempdir/geotrace | grep -v 'GEOLOCATION' | sed 's/| //g' | sed 's/|_//g' | sed 's/^ *//' | awk '{print $3,$4}' |
cut -d '(' -f 2 | cut -d ')' -f 1 | awk '{print $1}' | sed '/^$/d' | tr -d ' '); fi
if [ -n "$hoplist" ]; then
echo ''; for h in $(echo "$hoplist" | head -3); do
f_BOGON "${h}"; if [ $bogon = "TRUE" ] ; then
f_Long; echo "$h"; f_Long
if [[ ${h} =~ $REGEX_IP4 ]] ; then
sudo nmap -R -sP 2> /dev/null $h | grep -E "scan report|MAC Address" | sed '/Nmap scan report/{x;p;x;G}' | sed 's/Nmap scan report for //g' |
sed '/MAC Address/G'; else
sudo nmap -6 -R -sP 2> /dev/null $h | grep -E "scan report|MAC Address" | sed '/Nmap scan report/{x;p;x;G}' | sed 's/Nmap scan report for //g' |
sed '/MAC Address/G'; fi; fi; done
if ! [ $option_hop_details = "0" ]; then
curl -s "https://www.peeringdb.com/api/ixpfx?protocol__in=IPv4" > $tempdir/ix_pfx.json
jq -r '.data[] | .prefix, .ixlan_id' $tempdir/ix_pfx.json > $tempdir/ix_pfx
curl -s "https://www.peeringdb.com/api/ixpfx?protocol__in=IPv6" > $tempdir/ix_pfx6.json
jq -r '.data[] | .prefix, .ixlan_id' $tempdir/ix_pfx6.json >> $tempdir/ix_pfx
echo '' | tee -a ${out}
for i in $(echo "$hoplist" | sed '1,1d'); do
f_HOP "${i}"; echo ''; f_CLEANUP_FILES; done
echo ''; f_Long; echo "[+] ASNs"; for a in $(cat $tempdir/asns | sort -ug); do
f_AS_SUMMARY "${a}"; done; rm $tempdir/asns; fi; fi; done | tee -a ${out}; echo '' | tee -a ${out}; else
f_WARNING; fi; echo ''; f_removeDir; f_Long; f_Menu
;;
#************** DUBLIN TRACEROUTE *******************
t5)
f_makeNewDir ; f_Long
if [ $option_connect = "0" ] ; then
f_targetCONNECT; fi
if ! [ $option_connect = "0" ] ; then
echo -e -n "\n${B}Dublin Traceroute > Options > [1]${D} Set target Host | IP Address  ${B}| [2]${D} Target list  ${B}?${D}  " ; read option_target
if [ $option_target = "1" ] ; then
echo -e -n "\n${B}Target > ${G2}IPV4 ADDRESS / HOSTNAME  ${B}>>${D}  " ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list"
elif [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target > ${D}PATH TO FILE  ${B}>>${D}  " ; read input
targets="$input" ; fi
for x in $(cat "$targets") ; do
out="$outdir/ROUTES.DUBLIN_T.${x}.txt"; sudo ${PATH_dublin_t} -n 12 $x > $tempdir/d_t
echo '' | tee -a ${out}; f_Long | tee -a ${out} ; echo "[+]  $x  | [Dublin Traceroute] $(date)" | tee -a ${out} ; f_Long | tee -a ${out}
echo '' | tee -a ${out}; cat $tempdir/d_t | sed "/Starting dublin-traceroute/{x;p;x;G}" | awk -F', flow hash:' '{print $1}' | sed "/Flow ID/{x;p;x;G}" |
sed "s/'TTL expired in transit',//g" | sed "s/IP ID:/\n     IP ID:/g" | sed "/IP ID:/G" | sed "/*/G" | sed "/Saved JSON file/{x;p;x;}" | tee -a ${out} ; done
echo -e "\n"; else
f_WARNING; fi; echo ''; f_removeDir; f_Long; f_Menu
;;
#************** atk6-trace6  *******************
t6)
f_makeNewDir; f_Long; domain_enum="false"; option_detail="1"; target_type="hop"; bl_check="false"; targets=''
if [ $option_connect = "0" ] ; then
f_targetCONNECT; fi
if ! [ $option_connect = "0" ] ; then
echo -e -n "\n${B}Target > [1]${D} Set target IPv6 Address  ${B}| [2]${D} Target list  ${B}?${D}  " ; read option_target
if [ $option_target = "1" ] ; then
echo -e -n "\n${B}Target > ${D} IPv6 Address   ${B}>>${D}   " ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list"
elif [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target > ${D}PATH TO FILE  ${B}>>${D}  " ; read input
targets="$input" ; fi
echo -e "\n${B}Active Network Interfaces${D}\n"
ip -6 addr show | grep -s 'state UP' | cut -d ':' -f 2 | sed 's/^ *//'
echo -e -n "\n${B}Set  >  ${D}Network Interface -e.g. eth0  ${B}>>${D}  " ; read interface
echo -e -n "\n${B}Option  > ${G2} Hop Details${D}\n"
echo -e "${B} [1]${D} Look up Whois-, Geolocation- & RPKI- Info"
echo -e "${R} [0]${D} SKIP"; echo -e -n "\n${B}  ? ${D}  " ; read option_hop_details
if [ $option_hop_details = "1" ]; then
out="${outdir}/TRACE6_HOP_DETAILS.${file_date}.txt"; else
out="${outdir}/ROUTES_TRACE6.${file_date}.txt"; fi
for x in $(cat "$targets") ; do
echo '' | tee -a ${out}; sudo ${PATH_trace6} -t -d ${interface} ${x} > $tempdir/trace6
f_Long | tee -a ${out} ; echo -e "[+] ${x} [atk6-trace6] | $(date)" | tee -a ${out} ; f_Long | tee -a ${out}
cat $tempdir/trace6 | sed '/Trace6 for/{x;p;x;G}' | sed '/new MTU/{x;p;x;G}' | sed '/ping reply/{x;p;x;}' | tee -a ${out}
hoplist=$(awk -F' ' '{print $2}' $tempdir/trace6 | sed '/!!!/d' | sed '/???/d' | sed 's/^ *//' | sed '/^$/d')
if [ -n "$hoplist" ]; then
echo ''; for h in $(echo "$hoplist" | head -3); do
f_BOGON "${h}"; if [ $bogon = "TRUE" ] ; then
f_Long; echo "$h"; f_Long
sudo nmap -6 -R -sP 2> /dev/null $h | grep -E "scan report|MAC Address" | sed '/Nmap scan report/{x;p;x;G}' | sed 's/Nmap scan report for //g' |
sed '/MAC Address/G'; fi; done
if ! [ $option_hop_details = "0" ]; then
curl -s "https://www.peeringdb.com/api/ixpfx?protocol__in=IPv6" >> $tempdir/ix_pfx6.json
jq -r '.data[] | .prefix, .ixlan_id' $tempdir/ix_pfx6.json > $tempdir/ix_pfx; echo '' | tee -a ${out}
for i in $(echo "$hoplist" | sed '1,1d'); do
f_HOP "${i}"; echo ''; f_CLEANUP_FILES; done
echo ''; f_Long; echo "[+] ASNs"; for a in $(cat $tempdir/asns | sort -ug); do
f_AS_SUMMARY "${a}"; done; rm $tempdir/asns; fi; fi; done | tee -a ${out}; echo '' | tee -a ${out}; else
f_WARNING; fi; echo ''; f_removeDir; f_Long; f_Menu
;;
#************** NPING *******************
p1)
f_makeNewDir ; f_Long ; touch $tempdir/targets.list; out="${outdir}/NPING.txt"; declare -a nping_array=()
if [ $option_connect = "0" ] ; then
f_targetCONNECT; fi
if ! [ $option_connect = "0" ] ; then
echo -e "${B}Supported Target Types:${D}\n"
echo -e "IPv4 & IPv6 addresses \nHostnames \nNetwork addresses (CIDR notation, IPv4 only)"; f_Long
echo -e -n "\n${B}Target  > [1]${D}  Set Target ${B}| [2]${D}  Target List  ${B}?${D}  " ; read option_target
if [ $option_target = "1" ] ; then
echo -e -n "\n${B}Target  > ${G2}IPV4|V6 ADDRESS / HOSTNAME  ${B}>>${D}  " ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list" ; else
echo -e -n "\n${B}Target > ${G2}PATH TO FILE  ${B}>>${D} " ; read input ; targets="${input}" ; fi
echo -e "\n${B}Options > ${B}PROTOCOLS > ${G2}TCP\n"; echo -e "${B} [1]${D} TCP - Connect (non-root)"
echo -e "${B} [2]${D} TCP - SYN"; echo -e "${B} [3]${D} TCP - ACK"; echo -e "${B} [4]${D} TCP - PSH (PUSH)"
echo -e "${B} [5]${D} TCP - RST (RESET)"; echo -e "${R} [0]${D} SKIP"; echo -e -n "\n${B}  ? ${D}  " ; read option_tcp
if ! [ $option_tcp = "0" ] ; then
declare -a tcp_array=(); declare -a sport_tcp=(); declare -a dports_tcp=(); tcp_ping="true"
if [ $option_tcp = "2" ] ; then
flags="SYN"; tcp_array+=(--tcp --flags SYN)
elif [ $option_tcp = "3" ] ; then
flags="ACK"; tcp_array+=(--tcp --flags ACK)
elif [ $option_tcp = "4" ] ; then
flags="FIN"; tcp_array+=(--tcp --flags PSH)
elif [ $option_tcp = "5" ] ; then
flags="RST"; tcp_array+=(--tcp --flags RST); else
flags="CONNECT"; tcp_array+=(--tcp-connect); fi
echo -e -n "\n${B}TCP   > ${G2}Destination Port(s)${D}  - e.g. 25,80,135  ${B}>>${D}  " ; read d_ports_tcp
dest_tcp=$(echo $d_ports_tcp | tr -d ' ')
dports_tcp+=(-p ${dest_tcp}); else
tcp_ping="false"; fi
echo -e "\n\n${B}Options > ${B}PROTOCOLS > ${G2}UDP\n"
echo -e "${B} [1]${D} UDP"
echo -e "${R} [0]${D} SKIP"
echo -e -n "\n${B}  ? ${D}  " ; read option_udp
if ! [ $option_udp = "0" ] ; then
declare -a udp_array=(); declare -a sport_udp=(); declare -a dports_udp=(); udp_ping="true"; udp_array+=(--udp)
echo -e -n "\n${B}UDP   > ${G2}Destination Port(s)${D}  - e.g. 53,123  ${B}>>${D}  " ; read d_ports_udp
dest_udp=$(echo $d_ports_udp | tr -d ' ')
dports_udp+=(-p ${dest_udp}); else
udp_ping="false"; fi
echo -e "\n\n${B}Options > ${B}PROTOCOLS > ${G2}ICMP\n"
echo -e "${B} [1]${D} Echo       Request"
echo -e "${B} [2]${D} Timestamp  Request"
echo -e "${B} [3]${D} Mask       Request"
echo -e "${B} [4]${D} Router     Solicitation"
echo -e "${R} [0]${D} SKIP"
echo -e -n "\n${B}  ? ${D}  " ; read option_icmp
if ! [ $option_icmp = "0" ] ; then
declare -a icmp_array=(); icmp_ping="true"
if [ $option_icmp = "2" ] ; then
icmp_type="TIMESTAMP REQUEST"; icmp_array+=(--icmp --icmp-type time)
elif [ $option_icmp = "3" ] ; then
icmp_type="MASK REQUEST"; icmp_array+=(--icmp --icmp-type mask)
elif [ $option_icmp = "4" ] ; then
icmp_type="ROUTER SOL."; icmp_array+=(--icmp --icmp-type rout-sol); else
icmp_type="ECHO REQUEST"; icmp_array+=(--icmp --icmp-type echo); fi ; else
icmp_ping="false"; fi
echo -e -n "\n${B}Option  > Packets > ${G2}Number of packets  ${B}>>${D}  "; read packets
nping_array+=(-c ${packets})
f_Long; echo -e "\n${B}Options >\n"; echo -e "${G2} [1]${D} Proceed with current options"
echo -e "${B} [2]${D} Show more options"; echo -e -n "\n${B}  ? ${D}  " ; read choice
if [ $choice = "1" ] ; then
frag="AUTO"; mtu_size="DEFAULT"; data_payload="FALSE"; badsum_udp="FALSE"; source_port_udp="RANDOM"; sport_udp=''; badsum_tcp="FALSE"
source_port_tcp="RANDOM"; sport_tcp=''; win_size="DEFAULT"; else
echo -e "\n${B}Options > ${B} Packets > ${G2}Rate (Probes per Second)\n"
echo -e "${B} [1]${D} Set custom rate"
echo -e "${R} [0]${D} SKIP (default - 1 probe per second"
echo -e -n "\n${B}  ? ${D}  " ; read option_rate
if [ $option_rate = "1" ] ; then
echo -e -n "${G2}PACKETS PER SECOND  ${B}>>${D}  " ; read pps 
nping_array+=(--rate ${pps}); fi 
echo -e "\n${B}Options > ${B} Packets > ${G2}Fragmentation${D} (Not available in TCP-Connect Mode)\n"
echo -e "${B} [1]${D} Set 'Don't Fragment' Flag"
echo -e "${B} [2]${D} Set 'More Fragments' Flag"
echo -e "${R} [0]${D} SKIP"
echo -e -n "\n${B}  ? ${D}  " ; read option_frag
if [ $option_frag = "1" ] ; then
frag="DON'T FRAG."; nping_array+=(-df)
elif [ $option_frag = "2" ] ; then
frag="MORE FRAG."; nping_array+=(-mf); else
frag="AUTO"; fi
echo -e "\n${B}Options > ${B} Packets > ${G2}Payload (Data Length) ${D}  (Not available in TCP-Connect Mode)\n"
echo -e "${B} [1]${D} Set n bytes of random data"; echo -e "${R} [0]${D} SKIP (default)"; echo -e -n "\n${B}  ? ${D}  " ; read option_payload
if [ $option_payload = "1" ] ; then
echo -e -n "${G2}DATA LENGTH (BYTES)  ${B}>>${D}  " ; read data_length
nping_array+=(--data-length ${data_length}); data_payload="RANDOM: $data_length BYTES"; else
data_payload="FALSE"; fi
if [ $tcp_ping = "true" ] ; then
echo -e "\n\n${B}Options > ${G2} TCP ${B}> ${G2} Source Port / Checksum\n"
echo -e "${B} [1]${D} Spoof Source Port"; echo -e "${B} [2]${D} Send random invalid checksum"
echo -e "${B} [3]${D} BOTH"; echo -e "${R} [0]${D} SKIP"; echo -e -n "\n${B}  ? ${D}  " ; read option_tcp2
if [ $option_tcp2 = "1" ] || [ $option_tcp2 = "3" ] ; then
echo -e -n "${G2}TCP SOURCE PORT${D}  - e.g. 53  ${B}>>${D}  " ; read source_tcp
source_port_tcp="$source_tcp"; sport_tcp="-g $source_tcp"; else
source_port_tcp="RANDOM"; sport_tcp=''; fi
if [ $option_tcp2 = "2" ] || [ $option_tcp2 = "3" ] ; then
badsum_tcp="TRUE"; tcp_array+=(--badsum); else
badsum_tcp="FALSE"; fi
echo -e "\n${B}Options > ${G2}TCP WINDOW Size ${B}Not available in TCP-Connect Mode\n"
echo -e "${B} [1]${D} Set Custom WINDOW SIZE"
echo -e "${R} [0]${D} SKIP (Default)"
echo -e -n "\n${B}  ? ${D}  " ; read option_win
if [ $option_win = "1" ] ; then
echo -e -n "\n${B}TCP WINDOW SIZE${D} - e.g. 1480  ${B}>>${D}  "; read win_size
tcp_array+=(--win ${win_size}); else
win_size="DEFAULT"; fi; fi
if [ $udp_ping = "true" ] ; then
echo -e "\n\n${B}Options > ${G2} UDP ${B}> ${G2} Source Port / Checksum\n"
echo -e "${B} [1]${D} Spoof Source Port"
echo -e "${B} [2]${D} Send random invalid checksum"
echo -e "${B} [3]${D} BOTH"
echo -e "${R} [0]${D} SKIP"
echo -e -n "\n${B}  ? ${D}  " ; read option_udp2
if [ $option_udp2 = "1" ] || [ $option_udp2 = "3" ] ; then
echo -e -n "${G2}UDP SOURCE PORT${D}  - e.g. 53  ${B}>>${D}  " ; read source_udp
source_port_udp="$source_udp"; sport_udp="-g $source_udp"; else
source_port_udp="RANDOM"; sport_udp=''; fi
if [ $option_udp2 = "2" ] || [ $option_udp2 = "3" ] ; then
badsum_udp="TRUE"; udp_array+=(--badsum); else
badsum_udp="FALSE"; fi; fi; fi
echo '' | tee -a ${out}; f_Long | tee -a ${out} ; echo "[+]  NPING  |  $(date)" | tee -a ${out}
for t in $(cat $targets | sort -uV) ; do
x=$(echo $t | sed 's/http[s]:\/\///' | tr -d ' '); net_ip=$(echo $x | cut -d '/' -f 1)
if [[ ${net_ip} =~ $REGEX_IP4 ]] ; then
option_type="1"
elif [[ ${net_ip} =~ ":" ]] ; then
option_type="2"; else
option_type="3"; host4=$(host -t a $x | grep 'has address' | awk '{print $NF}' | tr -d ' ')
host6=$(host -t aaaa $x | grep 'has address' | awk '{print $NF}' | tr -d ' ') ; fi
f_Long
echo -e "\nNUM PACKETS:       $packets" | tee -a ${out}
echo "CUSTOM PAYLOAD:    $data_payload" | tee -a ${out}
echo "FRAGMENTATION:     $frag" | tee -a ${out}
if ! [ $option_tcp = "0" ] ; then
echo -e "\nDEST. PORTS TCP:   $dest_tcp" | tee -a ${out}
echo "SOURCE PORT TCP:   $source_port_tcp" | tee -a ${out}
echo "WINDOW SIZE:       $win_size" | tee -a ${out}
echo "BAD CHECKSUM TCP:  $badsum_tcp" | tee -a ${out}; fi
if ! [ $option_udp = "0" ] ; then
echo -e "\nDEST. PORTS UDP:   $dest_udp" | tee -a ${out}
echo -e "SOURCE PORT UDP:   $source_port_udp" | tee -a ${out}
echo "BAD CHECKSUM UDP:  $badsum_udp" | tee -a ${out} ; fi ; echo ''
if ! [ $option_tcp = "0" ] ; then
f_Long | tee -a ${out}; echo -e "$x" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' | tee -a ${out}; echo -e "TCP $flags" | tee -a ${out}
if [ $option_tcp = "1" ] ; then
if [ $option_type = "1" ]; then
${PATH_nping} ${tcp_array[@]} ${dports_tcp[@]} ${sport_tcp} ${nping_array[@]} ${x} > $tempdir/np; f_NPING_OUT | tee -a ${out}
elif [ $option_type = "2" ]; then
${PATH_nping} -6 ${tcp_array[@]} ${dports_tcp[@]} ${sport_tcp} ${nping_array[@]} ${x} > $tempdir/np; f_NPING_OUT | tee -a ${out}; else
if [ -n "$host4" ]; then
${PATH_nping} ${tcp_array[@]} ${dports_tcp[@]} ${sport_tcp} ${nping_array[@]} ${x} > $tempdir/np; f_NPING_OUT | tee -a ${out}; fi
if [ -n "$host6" ]; then
${PATH_nping} -6 ${tcp_array[@]} ${dports_tcp[@]} ${sport_tcp} ${nping_array[@]} ${x} > $tempdir/np; f_NPING_OUT | tee -a ${out}; fi; fi; else
if [ $option_type = "1" ]; then
sudo ${PATH_nping} ${tcp_array[@]} ${dports_tcp[@]} ${sport_tcp} ${nping_array[@]} ${x} > $tempdir/np; f_NPING_OUT | tee -a ${out}
elif [ $option_type = "2" ]; then
sudo ${PATH_nping} -6 ${tcp_array[@]} ${dports_tcp[@]} ${sport_tcp} ${nping_array[@]} ${x} > $tempdir/np; f_NPING_OUT | tee -a ${out}; else
if [ -n "$host4" ]; then
sudo ${PATH_nping} ${tcp_array[@]} ${dports_tcp[@]} ${sport_tcp} ${nping_array[@]} ${x} > $tempdir/np; f_NPING_OUT | tee -a ${out}; fi
if [ -n "$host6" ]; then
sudo ${PATH_nping} -6 ${tcp_array[@]} ${dports_tcp[@]} ${sport_tcp} ${nping_array[@]} ${x} > $tempdir/np; f_NPING_OUT | tee -a ${out}; fi; fi; fi; fi
if ! [ $option_udp = "0" ] ; then
f_Long | tee -a ${out}; echo -e "$x" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' | tee -a ${out}; echo -e "UDP" | tee -a ${out}
if [ $option_type = "1" ]; then
sudo ${PATH_nping} ${udp_array[@]} ${dports_udp[@]} ${sport_udp} ${nping_array[@]} ${x} > $tempdir/np; f_NPING_OUT | tee -a ${out}
elif [ $option_type = "2" ]; then
sudo ${PATH_nping} -6 ${udp_array[@]} ${dports_udp[@]} ${sport_udp} ${nping_array[@]} ${x} > $tempdir/np; f_NPING_OUT | tee -a ${out}; else
if [ -n "$host4" ]; then
sudo ${PATH_nping} ${udp_array[@]} ${dports_udp[@]} ${sport_udp} ${nping_array[@]} ${x} > $tempdir/np; f_NPING_OUT | tee -a ${out}; fi
if [ -n "$host6" ]; then
sudo ${PATH_nping} -6 ${udp_array[@]} ${dports_udp[@]} ${sport_udp} ${nping_array[@]} ${x} > $tempdir/np; f_NPING_OUT | tee -a ${out}; fi; fi; fi
if ! [ $option_icmp = "0" ] ; then
f_Long | tee -a ${out}; echo -e "$x" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' | tee -a ${out}; echo -e "ICMP $icmp_type" | tee -a ${out}
if [ $option_type = "1" ]; then
sudo ${PATH_nping} ${icmp_array[@]} ${nping_array[@]} ${x} > $tempdir/np; f_NPING_OUT | tee -a ${out}
elif [ $option_type = "2" ]; then
sudo ${PATH_nping} -6 ${icmp_array[@]} ${nping_array[@]} ${x} > $tempdir/np; f_NPING_OUT | tee -a ${out}; else
if [ -n "$host4" ]; then
sudo ${PATH_nping} ${icmp_array[@]} ${nping_array[@]} ${x} > $tempdir/np; f_NPING_OUT | tee -a ${out}; fi
if [ -n "$host6" ]; then
sudo ${PATH_nping} -6 ${icmp_array[@]} ${nping_array[@]} ${x} > $tempdir/np; f_NPING_OUT | tee -a ${out}; fi; fi ; fi ; echo '' | tee -a ${out}; done
echo ''; else
f_WARNING; fi; f_removeDir; f_Long; f_Menu
;;
p2)
f_makeNewDir ; f_Long ; touch $tempdir/targets.list; out="${outdir}/NPING_HT.txt"
echo -e -n "\n${B}Target  > [1]${D}  Set Target ${B}| [2]${D}  Target List  ${B}?${D}  " ; read option_target
if [ $option_target = "1" ] ; then
echo -e -n "\n${B}Target  > ${G2}IPV4 ADDRESS  ${B}>>${D}  " ; read input
echo "$input" > $tempdir/targets.list ; targets="$tempdir/targets.list" ; else
echo -e -n "\n${B}Target > ${G2}PATH TO FILE  ${B}>>${D} " ; read input
targets="${input}" ; fi
echo '' | tee -a ${out}; f_Long | tee -a ${out} ; echo "[+]  NPING  (hackertarget IP API) |  $(date)" | tee -a ${out}
for x in $(cat $targets | sort -uV) ; do
f_Long | tee -a ${out}; echo -e "$x\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' | tee -a ${out}
curl -s https://api.hackertarget.com/nping/?q=${x}${api_key_ht} | tee -a ${out}; echo '' | tee -a ${out} ; done
echo ''; f_removeDir; f_Long; f_Menu
;;
#************** NMAP - GENERAL PORT-/SERVICE-/VULNERABILITY SCAN OOPTIONS *******************
p3)
f_makeNewDir ; f_Long;
if [ -f $tempdir/nse ]; then
rm $tempdir/nse; fi
if [ $option_connect = "0" ] ; then
f_targetCONNECT; fi
if ! [ $option_connect = "0" ] ; then
declare -a nmap_array=()
echo "banner,http-server-header,https-redirect,ssl-cert," | sed 's/,/,\n/g' > $tempdir/nse
echo "T:80,T:443," | sed 's/,/,\n/g' > $tempdir/ports
echo -e "\n${B}Options > ${G2}Nmap Scan Types \n"
echo -e "${B} [1]${D} TCP Connect Scan (non-root)" ; echo -e "${B} [2]${D} Basic SYN Scan"
echo -e "${B} [3]${D} Service Version Scan"
echo -e "${B} [4]${D} Service- & OS Version Scan"
echo -e -n "\n${B}  ?${D}  " ; read scan_type
if [ $scan_type = "2" ]; then
nmap_array+=(-sS -sU -Pn -R --resolve-all --open)
elif [ $scan_type = "3" ]; then
nmap_array+=(-sV -sS -sU -Pn -R --resolve-all --version-intensity 4 --open)
elif [ $scan_type = "4" ]; then
nmap_array+=(-sV -sS -sU -Pn -O --osscan-limit --version-intensity 4 -R --resolve-all --open)
echo "ike-version,\nsmb-os-discovery,\nsmb-mbenum,\n" >> $tempdir/nse; else
nmap_array+=(-sT -Pn -R --resolve-all --open); fi
echo -e "\n${B}Options > ${G2}Mode \n"
echo -e -n "\n${G2}Mode   ${B}>  [1]${D}  IPv4   ${B}|  [2]${D}  IPv6  ${B}?${D}  " ; read option_ipv
if [ $scan_type = "1" ]; then
option_root="n"; ports="$ports_common_nonroot"; scripts="--script=${nse_basic_nonroot}"; else
echo -e "\n${B}Options IV > ${G2}Nmap Scripts \n"
echo -e "${B} [1]${D} Use default scripts only"
echo -e "${B} [2]${D} Run Script Scan, but SKIP Vulnerability Scans"
echo -e "${B} [3]${D} Script & Vulnerability Scan - FAST (script category: SAFE)"
echo -e "${B} [4]${D} Script & Vulnerability Scan - (script category: INTRUSIVE)"
echo -e -n "\n${B}  ?${D}  " ; read option_script
if [ $option_script = "3" ] || [ $option_script = "4" ]; then
echo -e "vulners,\nsmtp-strangeport,\nsmb-security-mode,\nsmb2-security-mode,\n" >> $tempdir/nse
if [ $option_script = "4" ]; then
echo -e "http-malware-host,\nftp-anon,\n" >> $tempdir/nse; fi; fi
echo -e "${B} [1]${D} Common Services (DNS, E-Mail Services, FTP, HTTP(S), Kerberos, NTP, RDP, SSH, Telnet, XMPP)"
echo -e "\n$ports_common\n" | sed 's/^/     /g' | fmt -s -w 40
echo -e "${B} [2]${D} Choose Ports by Service Categories"
echo -e "${B} [3]${D} Nmap Top 200 Ports"
echo -e "${B} [4]${D} All (TCP) Ports"
echo -e "${B} [5]${D} Enter Port Numbers and Protocols (TCP/UDP)"
echo -e -n "\n${B}  ?${D}  " ; read portChoice
if [ $portChoice = "1" ]; then
echo "$ports_common," | sed 's/,/,\n/g' > $tempdir/ports
elif [ $portChoice = "3" ]; then
ports="--top-ports 200"
elif [ $portChoice = "4" ]; then
ports="-p-"
elif [ $portChoice = "5" ]; then
echo -e -n "\n${B}Ports  > ${D} e.g. T:22,U:53,T:80 ${B}>>${D}  " ; read port_input
echo "$port_input," | sed 's/,/,\n/g' > $tempdir/ports; else
echo -e "\n${B}Options > Ports / Services Selection > ${G2}Basic Network Services\n"
echo -e "${B} [1]${D} CUPS, DNS, FTP, NTP, HTTP, SYSLOG"
echo -e "${B} [2]${D} Remote Access Services: RDP, rLOGIN, SSH, Telnet, VNC"
echo -e "${B} [3]${D} BOTH"
echo -e "${R} [0]${D} SKIP"
echo -e -n "\n${B}  ? ${D}  " ; read option_services1
if [ $option_services1 = "1" ] || [ $option_services1 = "3" ]; then
if ! [ $option_script = "1" ]; then
echo "cups-info,dns-recursion,ntp-info,redis-info," | sed 's/,/,\n/g' >> $tempdir/nse; fi
echo "U:53,U:123,T:20,T:21,T:53,T:80,T:443,T:514,T:6379," | sed 's/,/,\n/g' >> $tempdir/ports; fi
if [ $option_services1 = "2" ] || [ $option_services1 = "3" ]; then
if ! [ $option_script = "1" ]; then
echo "ssh-auth-methods,ssh2-enum-algos,rdp-ntlm-info,vnc-info," | sed 's/,/,\n/g' >> $tempdir/nse; fi
echo "T:22,T:23,T:135,T:513,T:3389,T:5900," | sed 's/,/,\n/g' >> $tempdir/ports; fi
echo -e "\n${B}Options > Ports / Services Selection >${G2} Communication Services\n"
echo -e "${B} [1]${D} E-Mail Services"
echo -e "${B} [2]${D} IRC, RTC, VOIP, XMPP"
echo -e "${B} [3]${D} BOTH"
echo -e "${R} [0]${D} SKIP"
echo -e -n "\n${B}  ? ${D}  " ; read option_services2
if [ $option_services2 = "1" ] || [ $option_services2 = "3" ]; then
echo -e -n "\n${B}Option > ${G2}SMTP Enumeration Target ${B} > ${G2}TARGET DOMAIN ${B}>>${D}   " ; read $t_domain
echo "smtp-commands.domain=$t_domain," >> $tempdir/script_args
if ! [ $option_script = "1" ]; then
echo "smtp-commands,smtp-ntlm-info,imap-capabilities,imap-ntlm-info,pop3-capabilities,pop3-ntlm-info," | sed 's/,/,\n/g' >> $tempdir/nse
if [ $option_script = "4" ]; then
echo -e "smtp-open-relay,\n" >> $tempdir/nse; fi; fi
echo "T:25,T:102,T:110,T:143,T:465,T:631,T:993,T:995," | sed 's/,/,\n/g' >> $tempdir/ports; fi
if [ $option_services2 = "2" ] || [ $option_services2 = "3" ]; then
if ! [ $option_script = "1" ]; then
echo "sip-methods,rtsp-methods,xmpp-info,skypev2-version,irc-info," | sed 's/,/,\n/g' >> $tempdir/nse; fi
echo "T:80,T:443,T:554,T:5060,T:5222,T:6665,U:4569," | sed 's/,/,\n/g' >> $tempdir/ports; fi
echo -e "\n${B}Options > Ports / Services Selection > ${G2} DB, Shares, Web-/Application- Servers & Server Cluster\n"
echo -e "${B} [1]${D} Data Bases, SMB- & NFS Shares"
echo -e "${B} [2]${D} Web Servers, AJP, Hadoop"
echo -e "${B} [3]${D} BOTH"
echo -e "${R} [0]${D} SKIP"
echo -e -n "\n${B}  ? ${D}  " ; read option_services3
if [ $option_services3 = "1" ] || [ $option_services3 = "3" ]; then
if ! [ $option_script = "1" ]; then
echo "ms-sql-info,ms-sql-ntlm-info,mysql-info,maxdb-info,smb-enum-shares,smb-ls,nfs-showmount,nfs-ls," | sed 's/,/,\n/g' >> $tempdir/nse
if [ $option_script = "4" ]; then
echo -e "mysql-empty-password, \nms-sql-empty-password,\n" >> $tempdir/nse; fi; fi
echo "T:445,T:1433,T:1434,T:3306,T:7210," | sed 's/,/,\n/g' >> $tempdir/ports; fi
if [ $option_services3 = "2" ] || [ $option_services3 = "3" ]; then
if ! [ $option_script = "1" ]; then
echo "ajp-headers,hadoop-datanode-info,hadoop-namenode-info,hadoop-jobtracker-info,hadoop-tasktracker-info,cassandra-info,docker-version,memcached-info,vmware-version,http-webdav-scan,http-generator," | sed 's/,/,\n/g' >> $tempdir/nse
if [ $option_script = "4" ]; then
echo "http-methods.test-all" >> $tempdir/script_args
echo "http-methods,http-cors,http-dombased-xss,http-stored-xss,http-enum,http-csrf,http-cross-domain-policy,xmlrpc-methods,rmi-vuln-classloader,mysql-empty-password," |
sed 's/,/,\n/g' >> $tempdir/nse; fi; fi
echo "U:123,T:21,T:22,T:23,T:25,T:53,T:80,T:139,U:161,T:443,T:445,T:1099,T:1433,T:1434,T:2375,T:3306,T:3389,T:6379,T:8009,T:8080,T:8443,T:9160,T:9800,T:10000,T:11211,T:5060,T:50070,T:50075," | sed 's/,/,\n/g' >> $tempdir/ports; fi
echo -e "\n${B}Options > Ports / Services Selection > ${G2} IoT & SCADA Devices, Bitcoin Nodes & Clients\n"
echo -e "${B} [1]${D} SCADA & IoT"
echo -e "${B} [2]${D} Bitcoin"
echo -e "${B} [3]${D} BOTH"
echo -e "${R} [0]${D} SKIP"
echo -e -n "\n${B}  ? ${D}  " ; read option_services4
if [ $option_services4 = "1" ] || [ $option_services4 = "3" ]; then
if ! [ $option_script = "1" ]; then
echo "bacnet-info,coap-resources,dicom-ping,iec-identify,knx-gateway-info,modbus-discover,iec-identify,s7-info," | sed 's/,/,\n/g' >> $tempdir/nse; fi
echo "T:102,T:502,T:2404,U:3671,U:5683,T:4242,U:47808," | sed 's/,/,\n/g' >> $tempdir/ports; fi
if [ $option_services4 = "2" ] || [ $option_services4 = "3" ]; then
echo -e "bitcoin-getaddr,\nbitcoin-info,\n" >> $tempdir/nse; echo -e "T:8333,\n" >> $tempdir/ports; fi; fi
echo ''; f_Long
echo -e -n "\n${B}Option  > ${G2} Exclude ports ${D} - e.g. T:22 to avoid a known SSH tarpit  ${B} [y] | [n]  ?${D}  " ; read option_exclude
if [ $option_exclude = "y" ]; then
echo -e -n "\n${B}Ports  > ${D} e.g. T:22-24 ${B}>>${D}  " ; read ex_port_input
exclude="--exclude-ports ${ex_port_input}"; fi
if ! [ $portChoice = "3" ] || ! [ $portChoice = "4" ]; then
ports=$(cat $tempdir/ports | sort -uV | tr '[:space:]' ' ' | sed 's/^ *//' | tr -d ' ' | rev | cut -c 2- | rev; echo ''); fi
nse_scripts=$(cat $tempdir/nse | sort -uV | tr '[:space:]' ' ' | sed 's/^ *//' | tr -d ' ' | rev | cut -c 2- | rev; echo '')
scriptargs=$(cat $tempdir/script_args | tr '[:space:]' ' ' | sed 's/,/ /g' | sed 's/^ *//'; echo '')
scripts="--script=${nse_scripts}"; script_args="--script-args ${scriptargs}"; fi
echo -e -n "\n${G2}Target ${B}>  ${D}Hostname(s)   ${B}|${D} IPv4 Address(es)  ${B}|${D}  Network(s)  ${B}>>${D}  " ; read target
f_RUN_NMAP "${target}"; fi
;;
#************** NMAP PORT SCAN (via hackertarget.com IP Tools API) *******************
p4)
f_makeNewDir ; f_Long ; echo -e -n "\n${B}Nmap > Target >${D} IPv4 ADDRESS  >>${D}  " ; read target
out="${outdir}/PORTSCAN_HT.${target}.txt"; f_NMAP_HT "${target}" | tee -a ${out}; echo -e "\n"; f_removeDir; f_Long; f_Menu
;;
#*************** NMAP - FIREWALK / TCP FLAGS, FRAGMENTATION, SOURCE PORT SPOOFING *******************
p5)
f_makeNewDir ; f_Long ; scripts=''
echo -e "\n${B}NMAP > ${G2} Firewalk, TCP Flags\n${D}"
if [ $option_connect = "0" ] ; then
f_targetCONNECT; fi
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
nmap_array+=(-6); echo -e -n "\n${G2}Target ${B}>  ${D}Hostname   ${B}|${D} IPv6 Address  ${B}>>${D}  " ; read target ; else
echo -e -n "\n${G2}Target ${B}>  ${D}Hostname   ${B}|${D} IPv4 Address  ${B}|${D}  Network  ${B}>>${D}  " ; read target ; fi
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
echo -e "\n\n${B}Options  > Firewalk >${G2}Number of filtered ports to probe\n"
echo -e "${B} [1]${D} All" ; echo -e "${B} [2]${D} Set number" ; echo -e -n "\n${B}  ?${D}  " ; read option_probe
if   [ $option_probe = "1" ] ; then
probes="-1" ; else
echo -e -n "\n${B}Set   > Num of probed ports ${D} e.g. 5 ${B}>>${D}  " ; read probes ; fi
scripts="--script=firewalk --traceroute --script-args=firewalk.max-probed-ports=${probes}" ; fi
if [ $scan_type = "1" ] || [ $scan_type = "3" ] ; then
echo -e "\n\n${B}Options  > ${G2} TCP Flags\n"
echo -e "${B} [1]${D} ACK"
echo -e "${B} [2]${D} FIN"
echo -e "${B} [4]${D} FIN & ACK"
echo -e "${B} [5]${D} WINDOW SCAN"
echo -e -n "\n${B}  ? ${D}  " ; read scan_flag
if [ $scan_flag = "1" ] ; then
flag="ACK SCAN" ; nmap_array+=(-sA)
elif [ $scan_flag = "2" ] ; then
flag="FIN SCAN" ; nmap_array+=(-sF)
elif [ $scan_flag = "3" ] ; then
flag="FIN SCAN" ; nmap_array+=(-sF) ; nmap2_array+=(--reason -sA)
elif [ $scan_flag = "4" ] ; then
flag="WINDOW SCAN" ; nmap_array+=(-sW) ; else
flag="VERSION SCAN" ; nmap_array+=(-sV) ; fi
echo -e "\n\n${B}Options > Other >${G2} Packet Fragmentation / Source Port\n"
echo -e "${B} [1]${D} Packet Fragmentation (length: 8bit)"
echo -e "${B} [2]${D} Source Port Spoofing"
echo -e "${B} [3]${D} BOTH"
echo -e "${R2} [0]${D} SKIP"
echo -e -n "\n${B}  ? ${D}  " ; read option_extra
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
f_WARNING ; fi ; f_removeDir; echo -e "\n"; f_Long; f_Menu
;;
q)
echo -e "\n${B}----------------------------------- Done -------------------------------------\n"
echo -e "                       ${BDim}Author - Thomas Wy, Feb 2022${D}\n\n" ; f_removeDir
break
;;
esac
done

#!/bin/bash
#-------------------------------  CONFIG -   -------------------------------

#**********************  API KEYS  ***********************
#*  hackertarget.com IP TOOLS  *  #Expected: api_key_ht='&apikey=APIkey'
    #api_key_ht='&apikey= '
#*  ipqualityscore.com  *
    #api_key_iqs=''
#*  projecthoneypot.org  *
    #api_key_honeypot=''

#**********************  CUSTOMIZE PATHS TO EXECUTABLES  ***********************
# * atk6-dump_dhcp6 *
    PATH_dump_dhcp6=$(command -v atk6-dump_dhcp6)
   #PATH_dump_dhcp6=""
# * atk6-dump_router6 *
    PATH_dump_router6=$(command -v atk6-dump_router6)
    #PATH_dump_router6=""
# * dublin-traceroute *
    PATH_dublin_t=$(command -v dublin-traceroute)
    #PATH_dublin_t=""
# * HTTPing *
    PATH_httping=$(command -v httping)
    #PATH_httping=""
# * ipcalc *
    PATH_ipcalc=$(command -v ipcalc)
    #PATH_ipcalc=""
# * Lynx *
    PATH_lynx=$(command -v lynx)
    #PATH_lynx=""
# * MTR *
    PATH_mtr=$(command -v mtr)
    #PATH_mtr=""
#*  netcat / nc *
    PATH_ncat=$(command -v nc)
    #PATH_ncat=
# * Nmap *
    PATH_nmap=$(command -v nmap)
    #PATH_nmap=""
# * Nping *
    PATH_nping=$(command -v nping)
    #PATH_nping=""
# * testssl.sh *
    PATH_testssl=$(command -v testssl)
    #PATH_testssl=""
# * tracepath *
    PATH_tracepath=$(command -v tracepath)
    #PATH_tracepath=""
# * WhatWeb *
    PATH_whatweb=$(command -v whatweb)
    #PATH_whatweb=""

#-------------------------------  CHECK FOR UNSATISFIED DEPENDENCIES  -------------------------------
f_ERROR_MESSAGE(){
local s="$*"
echo -e "\nERROR: $s is not installed on your system. Please make sure that at least the essential dependencies are satisfied."
echo -e "\nDependencies (essential): curl, dnsutils (installs dig & host), jq, ipcalc, lynx, nmap, openssl, whois"
echo -e "\nDependencies (recommended): dublin-traceroute, nc/netcat, mtr, testssl.sh, thc-ipv6, tracepath, whatweb\n"
}
if ! type curl &> /dev/null; then
f_ERROR_MESSAGE "curl"; f_showHELP; f_ERROR_MESSAGE "curl"; exit 1 ; fi
if ! type dig &> /dev/null; then
f_ERROR_MESSAGE "dnsutils"; f_showHELP; f_ERROR_MESSAGE "dnsutils"; exit 1 ; fi
if ! type jq &> /dev/null; then
f_ERROR_MESSAGE "jq"; f_showHELP; f_ERROR_MESSAGE "jq"; exit 1 ; fi
if [ -z ${PATH_nmap} ] ; then
f_ERROR_MESSAGE "Nmap"; f_showHELP; f_ERROR_MESSAGE "Nmap"; exit 1 ; fi
if [ -z ${PATH_ipcalc} ] ; then
f_ERROR_MESSAGE "ipcalc"; f_showHELP; f_ERROR_MESSAGE "ipcalc"; exit 1 ; fi
if ! type whois &> /dev/null; then
f_ERROR_MESSAGE "whois"; f_showHELP; f_ERROR_MESSAGE "whois"; exit 1 ; fi

#-------------------------------  VARIABLES  -------------------------------
#**********************  TEXT COLOUR  ***********************
#blue; default; green; red
B='\e[34m'; D='\e[0m'; G='\e[38;5;035m'; R='\e[31m'; bold="\e[1m"
#**********************  WORKING DIRECTORY  *****************
tempdir="${PWD}/drwho_temp"; outdir="${PWD}/drwho_temp"
#**********************  DEFAULTS  **************************
output_folder="not saving results"; option_connect="1"; conn="${G}true${D}"; report="false"; quiet_dump="false"
#**********************  USER AGENTS ***********************
ua_moz="Mozilla/5.0"
#**********************  REGEX  ***********************
REGEX_HOSTNAME="^[a-zA-Z0-9._-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,5}$"
REGEX_IP4="^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"
REGEX_IP4_HOST_NET="[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}+/{0,1}+[0-9]{0,2}"
REGEX_MAC="((([0-9a-fA-F]{2})[ :-]){5}[0-9a-fA-F]{2})|(([0-9a-fA-F]){6}[:-]([0-9a-fA-F]){6})|([0-9a-fA-F]{12})"
REGEX_MAIL="\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b"
REGEX_IP46='[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|'\
'([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|'\
'([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|'\
':((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|'\
'(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|'\
'1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))'
REGEX_IP6='(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|'\
'([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|'\
'([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|'\
':((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|'\
'(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|'\
'1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))'
# See https://stackoverflow.com/a/17871737
#**********************  NMAP - TARGET PORTS & NSE SCRIPTS  ***********************
ports_web="T:21,T:22,T:23,T:80,T:443,T:1099,T:3306,T:8080,T:8443"
nse_root="unusual-port,vulners"
nse_web_safe="http-apache-server-status,http-cookie-flags,http-php-version,http-mobileversion-checker,http-affiliate-id,http-referer-checker"
nse_web1="ftp-anon,http-auth,http-auth-finder,http-aspnet-debug,http-cors,http-csrf,http-dombased-xss,http-enum,http-malware-host,http-methods,ssh-hostkey,http-phpmyadmin-dir-traversal,http-slowloris-check,http-stored-xss,http-unsafe-output-escaping,http-webdav-scan,mysql-empty-password,xmlrpc-methods,rmi-vuln-classloader,ssh2-enum-algos"
nse_web2="http-jsonp-detection,http-open-proxy,http-backup-finder,smtp-strangeport,rpcinfo,vmware-version"
#**********************  DNS BLOCKLISTS  ***********************
blocklists="
all.bl.blocklist.de
all.s5h.net
auth.spamrats.com
b.barracudacentral.org
bl.spamcop.net
dnsbl.dronebl.org
dnsbl.tornevall.org
ix.dnsbl.manitu.net
phishing.rbl.msrbl.net
relays.bl.kundenserver.de
spam.dnsbl.sorbs.net
talosintelligence.com
tor.dan.me.uk
"
#**********************  SUBPAGES - CONTACTS  ***********************
subpages="
career
contact
contact-us
kontakt
legal
services
support
jobs
karriere
news
impressum
de/kontakt
en/contact
fr/contact
"
#-------------------------------  HELPER FUNCTIONS -------------------------------

#**********************  CHECK FOR / DOWNLOAD IX PREFIX LIST (SOURCE: PEERING DB)  *********
f_get_IX_PFX(){
ix_file_date=$(date -I)
if ! [ -f ${ix_file_date}.ix_pfx.txt ]; then
echo -e "\nDownloading IX Prefix List...\n"
curl -m 30 -sL "https://www.peeringdb.com/api/ixpfx?protocol__in=IPv4" > $tempdir/ix_pfx4.json
jq -r '.data[] | .prefix, .ixlan_id' $tempdir/ix_pfx4.json > ${ix_file_date}.ix_pfx.txt
curl -m 30 -sL "https://www.peeringdb.com/api/ixpfx?protocol__in=IPv6" > $tempdir/ix6.json
jq -r '.data[] | .prefix, .ixlan_id' $tempdir/ix6.json >> ${ix_file_date}.ix_pfx.txt; fi
}
#**********************  SET TARGET  ***********************
f_setTARGET(){
echo -e -n "\n${B}Target  >  [1]${D}  Set Target  ${B}|  [2]${D} Target List  ${B}?${D}  " ; read option_target
if [ $option_target = "1" ] || [ $option_target = "2" ]; then
if [ $option_target = "2" ]; then
echo -e -n "\n${B}Target  >  ${G}PATH TO FILE  ${D}e.g.  ./targets.txt  ${B}>>${D}  " ; read input
cat $input > $tempdir/targets_raw; else
echo -e -n "\n${G}TARGET  ${B}>>${D}  " ; read input
echo "$input" > $tempdir/targets_raw; fi
if [ -f $tempdir/targets_raw ]; then
f_prepareINPUT "$tempdir/targets_raw" > $tempdir/targets.list; else
echo -e "\nNo target provided"; fi; else
echo -e "\nInvalid choice, quitting...\n"; fi
}
f_prepareINPUT(){
sed 's/^[ \t]*//;s/[ \t]*$//' $1 | sed 's/  / /g' | sed 's/- /-/g' | sed 's/ -/-/g' | sed 's/,/\n/g' > $tempdir/input_tmp
if [ $choice = "w1" ]; then
grep -sEv ":|/" $tempdir/input_tmp |
grep -sEoi "\b(abuse-c|abuse-mailbox|admin-c|auth|author|fingerpr|form|irt-nfy|local-as|mbrs-by-ref|member-of|mnt-by|mnt-domains|mnt-irt|mnt-lower|mnt-nfy|mnt-ref|mnt-routes|notify|nserver|org|origin|person|ping-hdl|ref-nfy|tech-c|upd-to|zone-c)+;+[0-9a-z\-]{3,27}\b" | sort -uV; else
sed 's/;/\n/g' $tempdir/input_tmp | sed 's/http:\/\///g' | sed 's/https:\/\///g' |
sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' | cut -d ' ' -f 1  | sort -fiu; fi
}
#**********************  MANAGE TARGET INTERACTION  ***********************
f_targetCONNECT() {
echo -e "\n${B}Option  >${G}  Target Interaction  ${B}>${D}  Send packets from your IP to target systems?"
echo -e "\n${G}[1] YES${D}\n"
echo "(Recommended for option d) Full Domain Recon; required for most web server/tracerouting/port scanning options)"
echo -e "\n${R}[0] NO ${D}\n"
echo "(Interaction with target systems via 3rd party sources only)"
echo -e -n "\n\n${B}  ?${D}  " ; read option_connect
[[ -z $option_connect ]] && option_connect='0'
[[ $option_connect = '0' ]] && denied='target-connect mode only' && conn="${R}false${D}" || conn="${G}true${D}"
export option_connect ; export conn; export denied
}
f_WARNING(){
echo -e "\n${R}  Warning >${D} This option requires sending packets to target systems!"
echo -e "\n  Please deactivate safe mode via option c)" ; echo -e "\n  ${R}${IT}Aborting...${D}"
}
#**********************  SET TEMPORARY & PERMANENT DIRECTORIES  ***********************
f_makeNewDir(){
[[ -d $tempdir ]] && rm -rf $tempdir; mkdir $tempdir
}
f_removeDir(){
[[ -d $tempdir ]] && rm -rf $tempdir
}
#**********************  GENERATE REPORTS FROM SCRIPT OUTPUT  ***********************
f_REPORT(){
echo -e -n "\n${B}SET ${G}directory  >  ${D}HOME/${B}dir_name  >>${D}  " ; read dirname
if [ -n "$dirname" ]; then
[[ -d $HOME/$dirname ]] || mkdir $HOME/$dirname
outdir="$HOME/$dirname"; output_folder="$dirname"; report="true"
export outdir; export output_folder; export report; fi
}
#**********************  OUTPUT FORMATTING ***********************
f_countL(){
echo $(wc -l <<< "$1")
}
f_countW(){
echo $(wc -w <<< "$1")
}
f_HEADLINE(){
echo ''; f_Long; echo "[+]  $1"; f_Long; echo ''
}
f_HEADLINE2(){
echo ''; f_Long; echo -e "\n$1"
}
f_Long(){
echo -e "_______________________________________________________________________________\n"
}
f_Medium(){
echo -e "_______________________________________________________________\n"
}
f_Short(){
echo -e "\n____________________________________\n"
}
f_printCSV(){
echo "$1" | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' | sed 's/^\,//' | sed 's/ ,/,/g' | sed 's/, /,/g' | sed 's/,/, /g' | sed 's/^ *//'
}
f_printTARGET_TYPE(){
echo -e "\n"; f_Long; echo "++++++++   ASSUMED INPUT:  $1   ++++++++"; f_Long; echo -e "\nSearching...\n"
echo "$input_sorted" | tr  '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//' | fmt -w 60; echo ''
}
f_textfileBanner(){
echo -e "\n ---------------\n  drwho.sh\n---------------\n"
echo -e "https://github.com/ThomasPWy/drwho.sh  Author: Thomas Wy  Vers.4.2 (Mar 2023)"; f_Long
echo -e "\nDate:     $(date -R)"; f_CLIENT_INFO | tee $tempdir/pubip; echo -e "Target:   $1\n"
}
f_toLOWER(){
echo $(tr [:upper:] [:lower:] <<< "$1")
}
f_toUPPER(){
echo $(tr [:lower:] [:upper:] <<< "$1")
}

#**********************  ADDRESSES (IP, NETWORK, EMAIL, DOMAINS)  ***********************
f_DEAGGREGATE(){
local s="$*"; [[ -f $tempdir/ranges ]] && rm $tempdir/ranges
echo "$s" | egrep -s '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep '-' > $tempdir/v4_tmp
for n4 in $(sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n $tempdir/v4_tmp); do
${PATH_ipcalc} "$n4" | sed '/deaggregate/d' | sed '/^$/d'; done > $tempdir/ranges
[[ $(wc -w < $tempdir/ranges) -gt 1 ]] && f_Short || echo ''
cat $tempdir/ranges | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -s -w 40
}
f_EXTRACT_IP4(){
extract_all=$(f_EXTRACT_IP4_ALL "$1"); [[ -n "$extract_all" ]] && echo "$extract_all" | grep -sEo "$REGEX_IP4"
}
f_EXTRACT_IP4_ALL(){
[[ -f $1 ]] && extract4=$(grep -sEo "$REGEX_IP4_HOST_NET" $1) || extract4=$(grep -sEo "$REGEX_IP4_HOST_NET" <<< $1)
[[ -n "$extract4" ]] && echo "$extract4" | sort -u | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n
}
f_EXTRACT_IP6(){
[[ -f $1 ]] && addr_input=$(grep -sE "$REGEX_IP6" $1) || addr_input=$(grep -sE "$REGEX_IP6" <<< $1)
check_net=$(cut -s -d '/' -f 1 <<< $addr_input)
[[ -n "$check_net" ]] && extract6="$addr_input" || extract6=$(grep -sEo "$REGEX_IP6" <<< $addr_input)
[[ -n "$extract6" ]] && echo "$extract6" | sort -u
}
f_getDOMAIN(){
unset check_soa; unset try_name
name_trimmed=$(echo "$1" | awk -F'://' '{print $NF}' | sed 's/^www.//' | cut -d '/' -f 1)
try_name=$(echo "$name_trimmed" | rev | cut -d '.' -f -3 | rev)
check_soa=$(dig @1.1.1.1 soa +noall +answer +noclass +nottlid $try_name | grep 'SOA')
if [ -z "$check_soa" ]; then
try_name=$(echo "$name_trimmed" | rev | cut -d '.' -f -2 | rev)
check_soa=$(dig @1.1.1.1 soa +noall +answer +noclass +nottlid $try_name | grep 'SOA'); fi
[[ -n "$check_soa" ]] && echo "$try_name"
}
f_getEMAIL(){
[[ -f $1 ]] && get_em=$(grep -sEaio "$REGEX_MAIL" $1) || get_em=$(grep -sEaio "$REGEX_MAIL" <<< $1)
[[ -n "$get_em" ]] && echo "$get_em" | sed 's/^[ \t]*//;s/[ \t]*$//' | tr [:upper:] [:lower:] | sort -u
#tr '[:space:]' ' '; echo ''
}
f_getHNAME(){
rgex_hn="\b[a-zA-Z0-9._-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,5}\b"
[[ -f $1 ]] && get_hn=$(grep -sEaio "$rgex_hn" $1) || get_hn=$(grep -sEaio "$rgex_hn" <<< $1)
[[ -n "$get_hn" ]] && echo "$get_hn" | sed 's/^[ \t]*//;s/[ \t]*$//' | sort -u
}
f_getNET_RANGE(){
unset get_nrange; if [ -f $tempdir/whois.json ]; then
if [ $rir = "arin" ]; then
get_nrange=$(jq -r '.data.records[]? | .[] | select (.key=="NetRange") | .value' $tempdir/whois.json | tail -1); else
if [[ $(echo "$1" | cut -d '/' -f 1) =~ $REGEX_IP4 ]]; then
get_nrange=$(jq -r '.data.records[]? | .[] | select (.key=="inetnum") | .value' $tempdir/whois.json | tail -1); else
get_nrange=$(jq -r '.data.records[]? | .[] | select (.key=="inet6num") | .value' $tempdir/whois.json | tail -1); fi; fi
[[ -n "$get_nrange" ]] && echo "$get_nrange"; fi
}
f_getNETS(){
local f="$*"; sed '/source:/G' ${f} | sed '/inetnum:/{x;p;x;}' | sed '/inet6num:/{x;p;x;}' |
sed -e '/./{H;$!d;}' -e 'x;/netname:/!d'
}
f_getNETS4(){
local f="$*"; sed '/inetnum:/{x;p;x;}' ${f} | sed '/source:/G' | sed -e '/./{H;$!d;}' -e 'x;/inetnum:/!d'
}
f_getNETS6(){
local f="$*"; sed '/inet6num:/{x;p;x;}' ${f} | sed '/source:/G' | sed -e '/./{H;$!d;}' -e 'x;/inet6num:/!d'
}
f_printADDR(){
unset vers4; unset vers6
[[ -f $1 ]] && addr_input=$(grep -sE "$REGEX_IP46" $1) || addr_input=$(grep -sE "$REGEX_IP46" <<< $1)
if [ -n "$addr_input" ]; then
vers4=$(f_EXTRACT_IP4_ALL "$addr_input"); vers6=$(f_EXTRACT_IP6 "$addr_input"); netwrk=$(cut -s -d '/' -f 1 <<<$addr_input)
if [ -n "$netwrk" ]; then
[[ -n "$vers4" ]] && fmt -w 70 | sed G <<<$vers4; [[ -n "$vers6" ]] && fmt -w 70 | sed G <<<$vers6;  else
[[ -n "$vers4" ]] && fmt -w 60  <<<$vers4; [[ -n "$vers6" ]] && fmt -w 60 <<<$vers6; fi; fi
}
#**********************  CLIENT  ***********************
f_CLIENT_INFO(){
curl -s -m 7 "http://ip-api.com/json/?fields=4286465" > $tempdir/client.json; loc=$(jq -r '.country' $tempdir/client.json)
asn=$(jq -r '.as' $tempdir/client.json | cut -d ' ' -f 1 | sed 's/^*//' | sed 's/AS/AS /')
asname=$(jq -r '.asname' $tempdir/client.json)
is_tor=$(f_TOR "$(jq -r '.query' $tempdir/client.json)" | grep 'true' | grep -o 'TOR')
if [ $target_type = "web" ] || [ $domain_enum = "true" ]; then
[[ -n "$curl_ua" ]] && print_ua="$ua_moz" || print_ua="curl default"
echo -e "\nClient:   $(hostname) ($(uname -o)) | $(jq -r '.query' $tempdir/client.json) | $loc ($asn, $asname)"
echo -e "\ncURL:     User agent: $print_ua  $is_tor"; else
echo -e "\nCLIENT:\n\n$(hostname) ($(uname -o)) | $(jq -r '.query' $tempdir/client.json) | $loc ($asn, $asname) $is_tor "; fi
}
f_getSYSTEM_DNS(){
if ! type resolvectl &> /dev/null; then
grep 'nameserver' /etc/resolve.conf; else
resolvectl status | sed -e '/./{H;$!d;}' -e 'x;/Current DNS Server:/!d;' | sed '/setting:/d' | sed '/Scopes:/d' | sed '/DNSSEC/d' |
sed 's/DNS Servers:/DNS Servers:\n/' | sed 's/^ *//' | sed '/^$/d' | sed '/Link/{x;p;x}'; fi
}
f_IFLIST() {
f_IF_ADDR; f_IF_STATS; f_HEADLINE2 "ROUTES\n"
[[ $(uname -o) =~ "Android" ]] && ip route || nmap --iflist | tr -d '*' | sed -n '/ROUTES/,$p' | grep -E -v "ROUTES|lo" | sed '/METRIC/G'
}
f_IF_ADDR(){
echo -e "\nINTERFACE ADDRESSES\n"
ip -br addr show up | grep 'UP' | sed 's/UP/\n/' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/ /\n/g'
}
f_IF_STATS(){
echo -e "\n\nINTERFACE STATS\n"
ip -s addr show up scope global | grep -wv 'state DOWN' | sed '/</{x;p;x;}' | sed -e '/./{H;$!d;}' -e 'x;/valid_lft/!d;' |
grep -E -A 1 "<|RX:|TX:" | awk -F'group' '{print $1}' | cut -d ' ' -f 2- | sed 's/--//' | sed '/</{x;p;x;}' | sed 's/</\n\n/' |
sed '/TX:/{x;p;x;}'
}
#-------------------------------  MAIN MENU  -------------------------------

f_Menu(){
echo -e "${B}"; f_Long; echo -e "\n  ${B}Directory      >${D}  $output_folder"
echo -e "\n  ${B}TargetConnect  >  $conn\n"
echo -e "${B}    x)   ${D}${bold}General Target Info ${D} (Input: AS Numbers, IPs, Net- & Hostnames, CIDRs, Org-IDs)"
echo -e "\n${B}  Target-specific Information Gathering & Diagnostics:\n"
echo -e "${B}    a)   ${D}AS & IX Details, Prefix BGP Status"
echo -e "${B}    d)   ${D}Domain Recon"
echo -e "${B}  dns)   ${D}DNS Records, MX SSL"
echo -e "${B}   ip)   ${D}IPv4 Address Reputation, VHosts"
echo -e "${B}    m)   ${D}MTU Discovery"
echo -e "${B}    n)   ${D}Networks"
echo -e "${B}    o)   ${D}Other"
echo -e "${B}    p)   ${D}Port Scans, Firewalk"
echo -e "${B}    t)   ${D}Tracerouting"
echo -e "${B}    w)   ${D}Whois (Inverse-, Object- & Bulk Lookups)"
echo -e "${B}  www)   ${D}Web Server Health Check, HTTP Headers & SSL Certificates"
echo -e "\n${B}    c)   TOGGLE TARGET - CONNECT / NON-CONNECT MODE"
echo -e "   cc)   CLEAR THE SCREEN"
echo -e "    h)   HELP"
echo -e "    s)   SAVE RESULTS"
echo -e "    q)   QUIT${D}"
}

#-------------------------------  WHOIS  -------------------------------

#**********************  GET RIR & GENERAL WHOIS DATA  ***********************
f_getRIR(){
export rir=$(curl -s -m 10 --location --request GET "https://stat.ripe.net/data/rir/data.json?resource=$1" | jq -r '.data.rirs[0].rir' |
grep -sEo "RIPE|ARIN|AFRINIC|APNIC" | tr [:upper:] [:lower:])
}
f_get_RIPESTAT_WHOIS(){
curl -s -m 20 --location --request GET "https://stat.ripe.net/data/whois/data.json?resource=$1" > $tempdir/whois.json
}
#********************** ABUSE CONTACT FINDER **********************
f_abuse_cFINDER(){
local s="$*" ; echo ''; f_getRIR "$s"
if [ $rir = "lacnic" ]; then
whois -h whois.lacnic.net $s > $tempdir/lacnic_whois; abuse_contacts=$(f_printLACNIC_ABUSE_C "$tempdir/lacnic_whois"); else
abuse_contacts=$(curl -s -m 10 --location --request GET "https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=${s}" |
jq -r '.data.abuse_contacts[]' | tr '[:space:]' ' ' ; echo ''); fi
if [ -n "$abuse_contacts" ]; then
echo -e "\n$s ($rir_name)  =>  $abuse_contacts"; else
echo -e "\n$s ($rir_name)  -  No abuse contacts found"; fi
}
#**********************  WHOIS - OUTPUT FORMATTING  ***********************
f_whoisFORMAT(){
local f="$*"
sed 's/% Information related to /Information related to /' ${f} | sed '/Source:/d' | sed '/fax:/d' | sed '/remarks:/d' |
sed 's/% Abuse contact/Abuse contact/' | sed '/^#/d' | sed '/%/d' | sed '/^$/d' | sed '/Abuse contact/{x;p;x;G;}' |
sed 's/Abuse contact for .*. is/\[@\] /' |
sed '/Information related/i \_______________________________________________________________________________\n' |
sed '/Information related/G' | sed 's/Information related to/* /'
}
f_printWHOIS_TARGET(){
local f="$*"; grep -E "^in:|^i6:|^na:|^de:|^cy:|^ac:|^og:|^mb:" ${f} | sed 's/in:/nnn/g' | sed 's/i6:/nnn/g' | sed '/na:/a )' |
sed 's/na:/(/' | sed 's/de:/de~/' | sed 's/cy:/|/' | sed 's/mb:/|/' | sed 's/ac:/admin~/' | sed 's/og:/og~/' |
sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' | sed 's/nnn/\n\n\n/g' | sed 's/de~/\n\n/' | sed 's/de~//g' |
sed 's/admin~/| Admin:/' | sed 's/admin~//g' | sed 's/og~/| Org:/' | sed 's/og~//g' | sed 's/|/\n\n/' | sed 's/^ *//' |
sed 's/( / (/' | sed 's/ )/)/' | sed '/./,$!d'; echo ''
}
#**********************  WHOIS - RIR SPECIFIC (ARIN, LACNIC) ***********************
f_ARIN_WHOIS(){
unset net_handles
[[ -f $tempdir/arin_contacts ]] && rm $tempdir/arin_contacts; [[ -f $tempdir/net_list ]] && rm $tempdir/net_list
[[ -f $tempdir/whois ]] && rm $tempdir/whois; [[ -f $tempdir/arin_nets ]] && rm $tempdir/arin_nets
[[ -f $tempdir/arin_pocs ]] && rm $tempdir/arin_pocs; [[ -f $tempdir/arin_snets ]] && rm $tempdir/arin_snets
net_handles=$(jq -r '.data.records[]? | .[] | select (.key=="NetHandle") | .value' $tempdir/whois.json | sed '1,1d' | sort -u)
if [ -n "$net_handles" ]; then
for nh in $net_handles; do
if [ $target_type = "net" ] && [ $option_detail != "1" ]; then
if [ $option_netdetails5 = "2" ] || [ $option_netdetails5 = "3" ]; then
whois -h whois.arin.net -- "z + > ! $nh" > $tempdir/whois; f_SUBNETS "$nh" >> $tempdir/arin_snets; else
whois -h whois.arin.net -- "n ! $nh" > $tempdir/whois; fi; else
whois -h whois.arin.net -- "! $nh" > $tempdir/whois; fi
f_NET_INFO "${s}" >> $tempdir/arin_nets; f_POC "$tempdir/whois" >> $tempdir/arin_pocs; echo '' >> $tempdir/arin_pocs; done
[[ -f $tempdir/arin_nets ]] && cat $tempdir/arin_nets
if [ -f $tempdir/arin_pocs ]; then
[[ $target_type != "hop" ]] && echo '' && f_HEADLINE2 "CONTACT" || echo -e "\nCONTACT\n"; cat $tempdir/arin_pocs; fi; fi
}
f_LACNIC_WHOIS(){
local f="$*"
inetnum=$(grep -sEai -m 1 "^inetnum:|^inet6num:" ${f} | awk '{print $NF}' | sed 's/^[ \t]*//;s/[ \t]*$//')
owner=$(grep -sEai -m 1 "^owner:" ${f} | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
owner_cc=$(grep -sEai -m 1 "^country:" ${f} | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
responsible=$(grep -sEai -m 1 "^responsible:" ${f} | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
owner_c=$(grep -sEai -m 1 "^owner-c:" ${f} | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
owner_poc=$(grep -A 5 "$owner_c" ${f} | grep -sEao "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" | sort -u | tr '[:space:]' ' '; echo '')
if [ $target_type = "net" ]; then
created=$(tr -d ' ' | sed -e :a -e 's/\(.*[0-9]\)\([0-9]\{4\}\)/\1-\2/;ta' <<<$created)
echo -e "Net:          $inetnum (created: $created)"
if [[ ${net_ip} =~ $REGEX_IP4 ]]; then
net_mask=$(f_ipCALC "$net_addr")
v4_range=$(ipcalc -b -n $net_addr | grep -E "Network:|Broadcast:" | sed '/HostMin:/a -' | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' |
tr '[:space:]' ' ' | sed 's/^ *//'); echo -e "\nRange:        $v4_range ($net_mask)\n"; fi; f_NETGEO "$inetnum"
echo -e "\n\nOwner:        $owner, $owner_cc"; else
echo -e "\nNet:          $inetnum | $owner, $owner_cc"; fi
echo -e "\nResponsible:  $responsible,  $owner_poc"; [[ $target_type != "hop" ]] && f_ROUTE && f_printLACNIC_NS
}
f_printLACNIC_NS(){
echo ''; f_HEADLINE2 "NAME SERVERS (SOURCE: WHOIS)\n\n"
grep -E "^nserver:" $tempdir/whois | awk '{print $NF}' | tr -d ' ' | sort -uV | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -w 80 | sed G
}
f_printLACNIC_ABUSE_C(){
local ac="$*"
abusec=$(grep -sEai -m 1 "^abuse-c:" ${ac} | awk '{print $NF}' | tr -d ' ')
print_abusec=$(sed -e '/./{H;$!d;}' -e 'x;/person:/!d' ${ac} | grep -sEa "^nic-hdl.*|^e-mail:" | grep -a -A 1 "$abusec" |
grep -sEao "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" | sort -u | tr '[:space:]' ' '; echo '')
[[ -n "$print_abusec" ]] && echo "$print_abusec"
}
f_JPNIC_WHOIS(){
local adc="$*"
if [ -n "$adc" ]; then
whois -h whois.nic.ad.jp "KT749JP/e" > $tempdir/jpnic
if [ -f $tempdir/jpnic ]; then
jpn_name=$(grep -E "^c\." $tempdir/jpnic | grep 'Last' | cut -s -d ']' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
jpn_hdl=$(grep -E "^a\." $tempdir/jpnic | grep 'Handle' | awk '{print $NF}')
jpn_org=$(grep -E "^g\." $tempdir/jpnic | grep 'Organization' | cut -s -d ']' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
grep -E "\[TEL\]" $tempdir/jpnic | cut -s -d ']' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' > $tempdir/jpnic_poc
f_getEMAIL "$tempdir/jpnic" >> $tempdir/jpnic_poc
[[ -f $tempdir/jpnic_poc ]] && jpnic_poc=$(cat $tempdir/jpnic_poc | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' | sed 's/^ *//'; echo '')
if [ -n "$jpn_name" ] || [ -n "$jpn_org" ]; then
[[ $target_type != "hop" ]] && f_HEADLINE2 "CONTACT\n" || echo -e "\n\nCONTACT\n"
echo -e "\n$jpn_name ($jpn_hdl)  $jpn_org"
[[ -n "$tempdir/jpnic_poc" ]] && echo -e "\n$jpnic_poc\n"; fi; fi; fi
}

#**********************  WHOIS - POINTS OF CONTACT  ***********************
f_POC(){
local w="$*"
if [ $rir != "lacnic" ]; then
if [ $rir = "arin" ]; then
f_ORG "${w}"; else
unset orgname; unset poc_type; unset orgid
[[ -f $tempdir/org ]] && rm $tempdir/org; [[ -f $tempdir/irt ]] && rm $tempdir/irt; [[ -f $tempdir/role ]] && rm $tempdir/role
[[ -f $tempdir/mntner ]] && rm $tempdir/mntner; [[ -f $tempdir/person ]] && rm $tempdir/person
[[ -f $tempdir/r_no_addr ]] && rm $tempdir/r_no_addr; [[ -f $tempdir/p_no_addr ]] && rm $tempdir/p_no_addr
[[ -f $tempdir/mail1 ]] && rm $tempdir/mail1; [[ -f $tempdir/mail2 ]] && rm $tempdir/mail2
orgid=$(grep -sEa -m 1  "^organisation|^org:" ${w} | awk '{print $NF}' | tr -d ' ')
[[ $target_type = "as" ]] && whois_output=$(cat ${w}) || whois_output=$(sed -n '/% Information/,/% Information/p' ${w})
if [ $domain_enum = "true" ]; then
orgname=$(grep -sEa -m 1  "^org-name:" ${w} | awk '{print $NF}' | tr -d ' ')
[[ -n "$orgname" ]] && [[ "$hdl" = "$orgid" ]] && poc_type="org"; else
poc_type="default"; orgname=$(echo "$whois_output" | grep -sEa -m 1  "^org-name:" | awk '{print $NF}' | tr -d ' '); fi
[[ -n "$orgname" ]] && echo -e "$whois_output" | sed -e '/./{H;$!d;}' -e 'x;/org-name:/!d' > $tempdir/org
if [[ $(echo "$whois_output" | grep -Eac "^mntner:") -gt 0 ]]; then
echo "$whois_output" | sed -e '/./{H;$!d;}' -e 'x;/mntner:/!d' > $tempdir/mntner; fi
if [[ $(echo "$whois_output" | grep -Eac "^irt:") -gt 0 ]]; then
echo "$whois_output" | sed -e '/./{H;$!d;}' -e 'x;/irt:/!d' > $tempdir/irt; fi
if [[ $(echo "$whois_output" | grep -Eac "^person:") -gt 0 ]]; then
echo "$whois_output" | sed -e '/./{H;$!d;}' -e 'x;/person:/!d' > $tempdir/person
[[ $domain_enum = "true" ]] && [[ $(grep -sEa "^nic-hdl:" $tempdir/person | grep -c "$hdl") -gt 0 ]] && poc_type="person"; fi
if [[ $(echo "$whois_output" | grep -Eac "^role:") -gt 0 ]]; then
echo "$whois_output" | sed -e '/./{H;$!d;}' -e 'x;/role:/!d' > $tempdir/role
[[ $domain_enum = "true" ]] && [[ $(grep -sEa "^nic-hdl:" $tempdir/role | grep -c "$hdl") -gt 0 ]] && poc_type="role"; fi
if [ $domain_enum = "true" ]; then
[[ $poc_type = "org" ]] && f_ORG "$tempdir/org"; [[ $poc_type = "role" ]] && f_printPOCS "$tempdir/role"
[[ $poc_type = "person" ]] && f_printPOCS "$tempdir/person"
[[ $poc_type != "org" ]] && [[ -n "$orgname" ]] && adm_org=$(f_ORG_SHORT "$tempdir/org") && echo -e "Org:  $adm_org\n"; else
echo ''; f_HEADLINE2 "CONTACT"; [[ -f $tempdir/org ]] && f_ORG "$tempdir/org"
if [ $target_type = "as" ] && [[ -n "$orgname" ]]; then
[[ -f $tempdir/role ]] && grep -sEav "^address:" $tempdir/role > $tempdir/r_no_addr && f_printPOCS "$tempdir/r_no_addr"
[[ -f $tempdir/person ]] && grep -sEav "^address:" $tempdir/person > $tempdir/p_no_addr && f_printPOCS "$tempdir/p_no_addr"; else
[[ -f $tempdir/irt ]] && f_printPOCS "$tempdir/irt"; [[ -f $tempdir/mntner ]] && f_printPOCS "$tempdir/mntner";
[[ -f $tempdir/role ]] && f_printPOCS "$tempdir/role"; [[ -f $tempdir/person ]] && f_printPOCS "$tempdir/person"
if ! [ -f $tempdir/org ]; then
if [[ $(sed -n '/route:/,$p' ${w} | sed -e '/./{H;$!d;}' -e 'x;/org-name:/!d' | grep -sEac "^org-name:") -gt 0 ]]; then
sed -n '/route:/,$p' ${w} | sed -e '/./{H;$!d;}' -e 'x;/org-name:/!d' > $tempdir/route_org
echo -e "\nORGANISATION (FOR ROUTE)"; f_ORG "$tempdir/route_org"; fi; fi; fi; fi; fi
grep -sEa -m 1  "^OrgId:|^org:|^organisation:" ${w} | awk '{print $NF}' | tr -d ' ' | sort -u >> $tempdir/org_ids
[[ $domain_enum = "true" ]] && echo '' && f_Medium && echo ''; fi
}
f_ADMIN_C(){
if ! [ $rir = "arin" ] && ! [ $rir = "lacnic" ]; then
timeout 30 timeout 10 whois -h whois.$rir.net -- "-F $1" | tr -d '*' | sed 's/^ *//' > $tempdir/adm
ad_name=$(grep -sEa "^pn:|^ro:" $tempdir/adm | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ')
ad_contact=$(grep -sEa "^ph:|^am:" $tempdir/adm | cut -d ':' -f 2- | sed 's/^ *//' | sort -u | head -3 | tr '[:space:]' ' ')
ad_addr=$(sed -n '/ad:/,/nh:/p' $tempdir/adm | grep -sEa "^ad:|^\+" | cut -d ':' -f 2- | cut -d '+' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' |
tr '[:space:]' ' '; echo '')
adm_type=$(grep -sEao "^pn:|^ro:" $tempdir/adm | sed 's/pn:/PERSON/' | sed 's/ro:/ROLE/' | tr -d ' ')
adm_mnt=$(grep -sEa -m 1 "^mb:" $tempdir/adm | awk '{print $NF}' | sed 's/^[ \t]*//;s/[ \t]*$//')
if [ $target_type = "other" ]; then
echo -e "$ad_name $ad_contact"
elif [ $target_type = "whois_target" ]; then
echo -e "[$adm_type]  $ad_name ($1) $ad_contact"; else
echo -e "\n$ad_name ($1)  $ad_contact"; fi; echo -e "\n$ad_addr\n\nMnt: $adm_mnt"; fi
}
f_getORG(){
unset target_org
if [ -f $tempdir/whois.json ]; then
if [ $rir = "lacnic" ]; then
target_org=$(jq -r '.data.records[]? | .[] | select (.key=="owner") | .value' $tempdir/whois.json | head -1)
elif [ $rir = "arin" ]; then
if [ $option_detail = "0" ] || [ $target_type = "hop" ]; then
target_org=$(jq -r '.data.records[]? | .[] | select (.key=="OrgId") | .value' $tempdir/whois.json | grep -E -v "ARIN|APNIC|RIPE|AFRINIC|LACNIC" | tail -1); else
target_org=$(jq -r '.data.records[]? | .[] | select (.key=="OrgId") | .value' $tempdir/whois.json | grep -E -v "ARIN|APNIC|RIPE|AFRINIC|LACNIC" | sort -u); fi; else
o_id=$(jq -r '.data.records[]? | .[] | select (.key=="org") | .value' $tempdir/whois.json | head -1)
if [ $option_detail != "0" ]; then
[[ -n "$o_id" ]] && whois -h whois.$rir.net -- "--no-personal $o_id" > $tempdir/whois_org && target_org=$(f_ORG_SHORT "$tempdir/whois_org"); fi; fi; fi
if [ -z "$target_org" ]; then
if  [ -f $tempdir/pwhois ]; then
pwhois_org=$(grep -sEa "^Org-Name:" $tempdir/pwhois | cut -s -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
pwhois_net=$(grep -sEa "^Net-Name:" $tempdir/pwhois | cut -s -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
pwhois_as=$(grep -sEa "^AS-Org-Name:" $tempdir/pwhois | cut -s -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//'); fi 
[[ -n "$pwhois_org" ]] && [[ "$pwhois_org" != "$pwhois_net" ]] && target_org="$pwhois_org"
[[ -z "$pwhois_org" ]] && [[ -f $tempdir/geo.json ]] && target_org=$(jq -r '.org' $tempdir/geo.json)
[[ -z "$pwhois_org" ]] && [[ -n "$pwhois_as" ]] && target_org="$pwhois_as"; fi; [[ -n "$target_org" ]] && echo "$target_org"
}
f_getRIR_OBJECTS(){
local f="$*"; rir_objects=$(grep -E "^oa:|^og:|^ac:|^tc:|^mb:|^it:|^abuse-c:|^abuse-mailbox|^admin-c:|^irt:|^mnt-by:|^mnt-lower:|^org:|^origin:|^tech-c:|upd-to:)" ${f} | sed '/RIPE-NCC-*/d' | sed 's/ac:/admin-c:/' | sed 's/oa:/org:/' | sed 's/og:/org:/' | sed 's/tc:/tech-c:/' | sed 's/mb:/mnt-by:/' |
sed 's/it:/irt-/' | sed 's/irt:/irt-/' | sed '/^$/d' | tr ':' ';' | tr -d ' ' | sort -uV | tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//')
if [ -n "$rir_objects" ]; then
printRIR_OBJ=$(echo "$rir_objects" | sed 's/ /  /g' | sed G)
if [ $domain_enum = "true" ]; then
n_name=$(grep -sE -m1 "^netname:" ${f} | awk '{print $NF}' | tr -d ' '); echo ''; f_HEADLINE2 "$n_name POCs ($(f_toUPPER "$rir"))\n\n"; else
if [ $target_type = "other" ]; then
echo -e "POCs:\n"
elif [ $target_type = "whois_target" ]; then
f_HEADLINE2 "$x POC OBJECTS ($(f_toUPPER "$rir"))\n\n"; else
echo ''; f_HEADLINE2 "$(f_toUPPER "$rir") POCs (Searchable in option [w1])\n\n"; fi; fi; echo -e "$printRIR_OBJ" | fmt -s -w 80; echo ''; fi
}
f_grepRIR_OBJECTS(){
local f="$*"; grep -sEv ":|/" ${f} |
grep -sEoi "\b(abuse-c|abuse-mailbox|admin-c|auth|author|fingerpr|form|irt-nfy|local-as|mbrs-by-ref|member-of|mnt-by|mnt-domains|mnt-irt|mnt-lower|mnt-nfy|mnt-ref|mnt-routes|notify|nserver|org|origin|person|ping-hdl|ref-nfy|tech-c|upd-to|zone-c)+;+[0-9a-z\-]{3,27}\b" | sort -uV 
}
f_ORG(){
local f="$*"
if [ $rir != "lacnic" ]; then
unset mailbox; unset mnt_by; unset peering_info
org_name=$(grep -Ea -m 1 "^OrgName:|^org-name:|^owner:" ${f} | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
if [ -n "$org_name" ]; then
if [ $rir = "arin" ]; then
arin_addr=$(grep -sEa "^OrgName:|^OrgId:|^Address:|^City:|^StateProv:|^PostalCode:|^Country:" ${f} | sed '/OrgId:/a )nnn___' | sed '/OrgId:/i (' |
sed '/^City:/i,' | sed '/^City:/a __' | sed '/^Country:/i,' | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' | sed 's/___/ /g' |
sed 's/__//g' | sed 's/ ,/,/g' | sed 's/( /(/' | sed 's/ )/)/' | sed 's/nnn/\n\n/'; echo '')
if [ $option_detail = "2" ]; then
arin_poc=$(grep -sEa "AbuseName:|AbuseEmail:|AbusePhone:|TechName:|TechEmail:|TechPhone:" ${f} | sed '/AbuseName:/i nnn' | sed '/AbuseName:/a nnn__' |
sed '/TechName:/i nnn' | sed '/TechName:/a nnn__' | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' |
tr '[:space:]' ' ' | sed 's/nnn/\n\n/g' | sed 's/^ *//' | sed 's/__//' | sed 's/^/  /'; echo '')
routing_mail=$(f_getEMAIL "$(grep -sEa "^OrgRoutingEmail:|^RoutingEmail:" ${f})"); else
abuse_ph=$(grep -sEa "AbusePhone:" ${f} | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | sort -u | tr '[:space:]' ' ')
abuse_mail=$(grep -sEa "AbuseEmail:" ${f} | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | sort -u | tr '[:space:]' ' ')
arin_tech=$(grep -s -m 3 "TechEmail:" ${f} | grep -sEo "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" |
sort -u | tr '[:space:]' ' '; echo ''); fi
echo -e "\n$arin_addr"
if [ $option_detail = "2" ]; then
echo -e "$arin_poc\n"; [[ -n "$routing_mail" ]] && echo -e "  Routing\n\n   $routing_mail"; else
echo -e "\n  Abuse: $abuse_ph $abuse_mail\n"; echo -e "  Tech:  $arin_tech\n"; fi; else
mailbox=$(f_getEMAIL "$f"); grep -sEa "^organisation:|^org-name:|^org-type:|^country:|^address:|^phone:|^mnt-by:" $f |
grep -sEv "RIPE-NCC-HM-MNT|RIPE-NCC-LEGACY-MNT" | sed '/organisation:/i nnn' |
sed '/org-type:/i (' | sed '/org-type:/a )' | sed '/org-name:/i __-__' | sed '/address:/i ==' | sed '/phone:/i |' |
sed '/mnt-by:/i |' | sed '/country:/i ,' | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' |
sed 's/nnn/\n\n/g' | sed 's/==/\n\n/' | sed 's/== //g' | sed 's/==//g' | sed 's/|/\n\n/' | sed 's/( / (/' |
sed 's/ )/)/' | sed 's/__/ /g' | sed 's/^ *//' | sed 's/ , /, /'; echo ''; [[ -n "$mailbox" ]] && echo -e "\n$mailbox"
if [ $target_type = "as" ]; then
peering_info=$(grep -sEa "^remarks:" ${f} | grep -sEai -A 1 "peering" |
grep -sEao "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" | sort -u | tr '[:space:]' ' ')
[[ -n "$peering_info" ]] && echo -e "\nPeering Info: $peering_info"; fi; fi; fi; fi
}
f_ORG_SHORT(){
local f="$*"
orgn=$(grep -Ea -m 1 "^org-name:" ${f} | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
orgid=$(grep -Ea -m 1 "^organisation:" ${f} | awk '{print $NF}' | sed 's/^[ \t]*//;s/[ \t]*$//')
if [ -n "$orgn" ]; then
sed -e '/./{H;$!d;}' -e 'x;/route:/d' ${f} | sed -e '/./{H;$!d;}' -e 'x;/org-name:/!d' > $tempdir/org_temp
if [ -f $tempdir/org_temp ]; then
org_geo=$(grep -sEa -m 1 "^country:" $tempdir/org_temp | awk '{print $NF}' | sed 's/^[ \t]*//;s/[ \t]*$//')
org_mail=$(f_getEMAIL "$tempdir/org_temp")
org_ph=$(grep -sEa -m 1 "^phone:" $tempdir/org_temp | cut -d ':' -f 2- | sed 's/^ *//')
[[ -z "$org_geo" ]] && org_geo=$(grep -sEa "^address:" $tempdir/org_temp | tail -1 | awk '{print $NF}' | sed 's/^[ \t]*//;s/[ \t]*$//')
if [ $target_type = "other" ] || [ $target_type = "whois_target" ]; then
org_address=$(grep -sEa "^address:" $tempdir/org_temp | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' '; echo '')
if [ $target_type = "whois_target" ]; then
echo -e "[ORG]  $orgn  ($orgid), $org_ph $org_mail\n\n$org_address\n"; else
echo -e "$orgn  ($orgid), $org_ph $org_mail\n\n$org_address\n"; fi; else
[[ $option_detail = "2" ]] && echo "$orgn ($orgid), $org_geo" || echo "$orgn ($orgid), $org_geo  $org_ph $org_mail"; fi; fi; fi
}
f_printPOCS(){
local f="$*"
[[ -f $tempdir/poc_add ]] && rm $tempdir/poc_add; unset abuse_mbox; unset notify; unset upd_to; unset whois_auth
abuse_mbox=$(f_getEMAIL "$(grep -sEa "^abuse-mailbox:" ${f})"); upd_to=$(f_getEMAIL "$(grep -sEa "^upd-to:" ${f})")
notify=$(grep -sEa "^notify:" ${f} | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | sort -u | tr '[:space:]' ' '; echo '')
whois_auth=$(grep -sEa "^auth:" ${f} | awk '{print $NF}' |
sed 's/^[ \t]*//;s/[ \t]*$//' | sort -u | tr '[:space:]' ' '; echo '')
poc_descr=$(grep -sEa "^descr:" ${f} | head -1 | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
grep -sEa "^person:|^role:|^mntner:|^irt:|^address:|^phone:|^e-mail:|^nic-hdl:|^mnt-by:" ${f} |
grep -sEiav "RIPE-NCC-LEGACY-MNT|RIPE-NCC-HM-MNT" | sed '/person:/i nnn' |  sed '/role:/i nnn' | sed '/mntner:/i nnn' |
sed '/irt:/i nnn' | sed '/address:/i ==' | sed '/phone:/i |' | sed '/e-mail:/i |' | sed '/nic-hdl:/i |' |
sed '/mnt-by:/i | MNT~~' | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' | sed 's/nnn/\n\n/g' |
sed 's/==/\n\n/' | sed 's/== //g' | sed 's/==//g' | sed 's/|/\n\n/' | sed 's/( / (/' | sed 's/ )/)/' | sed 's/~~/:/g' |
sed 's/^ *//'; echo ''; [[ -n "$poc_descr" ]] && echo -e "DESCR:  $poc_descr" || echo ''
[[ -n "$abuse_mbox" ]] && echo -e "ABUSE: $abuse_mbox" > $tempdir/poc_add
[[ -n "$notify" ]] && echo -e "NOTIFY: $notify" >> $tempdir/poc_add
[[ -n "$whois_auth" ]] && [[ $(echo "$whois_auth" | wc -w) -lt 3 ]] && echo -e "AUTH: $whois_auth" >> $tempdir/poc_add
[[ -f $tempdir/poc_add ]] && poc_add=$(cat $tempdir/poc_add | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' '; echo '')
[[ -n "$poc_add" ]] && echo -e "$poc_add\n"
[[ -n "$whois_auth" ]] && [[ $(echo "$whois_auth" | wc -w) -gt 2 ]] && echo -e "AUTH: $whois_auth\n"
}
#**********************  WHOIS - phwois.org  ***********************
f_pwhoisBULK(){
local s="$*" ; echo -e "begin" > $tempdir/addr.list; cat ${s} >> $tempdir/addr.list
echo "end" >> $tempdir/addr.list ; netcat whois.pwhois.org 43 < $tempdir/addr.list > $tempdir/addr.txt
if [ $domain_enum = "true" ]; then
grep -E "^IP:|Origin-AS:|^Prefix:|^Org-Name:|^Net-Name:" $tempdir/addr.txt | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' |
sed 's/IP:/\n\n/g' | sed 's/Origin-AS:/|/g' | sed 's/Prefix:/|/g' | sed 's/Org-Name:/|/g' | sed 's/Net-Name:/|/g' |
sed 's/^ *//' > $tempdir/pwhois
[[ -f $tempdir/pwhois ]] && echo '' >> $tempdir/pwhois; else
echo ''; f_Long
grep -sEa "^IP:|^Origin-AS:|^Prefix:|^AS-Org-Name:|^Org-Name:|^Net-Name:|^Geo-CC:|^Country-Code:" $tempdir/addr.txt | sed 's/IP: /nnn/' |
sed 's/Origin-AS:/ - AS/' | sed 's/Prefix:/|/' | sed 's/AS-Org-Name:/| AS ORG__/' | sed 's/Org-Name:/| Org__/' | sed 's/Net-Name:/| NET__/' |
sed 's/Country-Code:/|/' | sed 's/Geo-CC:/|/' | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' | sed 's/nnn/\n\n/g' |
sed 's/|/\n\n/' | sed 's/__/:/g' | sed 's/^ *//'; echo ''; fi
}
f_printPWHOIS_ORG(){
local f="$*"
grep -sEa "^Org-ID:|^Org-Name:|^Source:|^Country:|^Abuse-0-Handle:|^Abuse-0-Name:|^Abuse-0-Email:|^Tech-0-Handle:|^Tech-0-Name:|^Tech-0-Email:|NOC-0-Handle:" ${f} |
sed '/Placeholder/d' | sed '/DUMY-RIPE/d' | sed 's/Org-ID:/Org-ID~/' | sed 's/Org-Name:/ONAME~/' | sed 's/Country:/|/' |
sed 's/Source:/|/' | sed 's/Abuse-0-Handle:/Abuse~/' | sed 's/Tech-0-Handle:/Tech~/' | sed 's/NOC-0-Handle:/| NOC~/' |
cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' | sed 's/Org-ID~/\n\n\n+ ID:/g' | sed 's/ONAME~ /\n\n/g' |
sed 's/Abuse~/\n\nAbuse:/g' | sed 's/Tech~/\n\nTech: /g'  | sed '/./,$!d' | sed 's/^/  /' | sed 's/  +/+/' | sed 's/~/:/g'; echo ''
}
f_netBLOCKS(){
unset v4_ranges
v4_blocks=$(whois -h whois.pwhois.org "netblock org-id=$1" | grep '|' | cut -d '|' -f 1,2 | sed '/Net-Range/{x;p;x;G}')
if [ -z "$v4_blocks" ] || [ $target_type != "other" ]; then
whois -h whois.pwhois.org "netblock6 org-id=$1" |
grep -E "^Netblock-Record:|^Net-Range:|^Net-Name:|^Net-Handle:|^Net-Org-ID:|^Net-Source:" > $tempdir/blocks6
v6_blocks=$(sed '/Netblock-Record:/a ====' $tempdir/blocks6 | sed '/Netblock-Record/d' | tr '[:space:]' ' ' | sed 's/==/\n\n/g' |
grep -i -w "$1" | sed 's/==/\n/g' | sed 's/Net-Range:/\n\n/g' | sed 's/Net-Name:/\n\n/g' | sed 's/Net-Handle:/|/g' | sed 's/Net-Org-ID:/|/g' |
sed 's/Net-Source:/|/' | sed 's/^ *//'); fi
[[ -n "$v4_blocks" ]] || [[ -n "$v6_blocks" ]] && f_HEADLINE "$1  |  NETBLOCKS  [whois.pwhois.org]"
if [ -n "$v4_blocks" ]; then
ranges=$(echo "$v4_blocks" | grep '*>' | awk -F' ' '{print $2 $3 $4}')
[[ $target_type != "other" ]] && echo -e "\n-- IPV4 --\n" || echo ''; echo -e "$v4_blocks\n"
for i in $ranges ; do
${PATH_ipcalc} "$i" | sed '/deaggregate/d' | sed '/^$/d'; done > $tempdir/v4_ranges
v4_count=$(wc -w < $tempdir/v4_ranges )
[[ $v4_count -gt 2 ]] && v4_ranges=$(cat $tempdir/v4_ranges | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -s -w 40)
if [ -n "$v4_ranges" ]; then
echo -e "\n__________________________________________________________________\n"
if [ $target_type = "other" ]; then
[[ $v4_count -gt 8 ]] && echo -e "\n$v4_ranges\n" || echo -e "$v4_ranges\n"; else
[[ $v4_count -gt 8 ]] && echo -e "\n$v4_ranges\n" || echo -e "$v4_ranges\n";
[[ -n "$v6_blocks" ]] && echo -e "__________________________________________________________________\n" || echo ''; fi; else
echo '' ; cat $tempdir/v4_ranges; echo ''; fi; fi
if [ -n "$v6_blocks" ]; then
[[ $target_type != "other" ]] && echo -e "\n-- IPV6 --\n\n" || echo -e "\n"; echo -e "$v6_blocks\n" | sed '/./,$!d'; fi
}
f_whoisTABLE(){
local s="$*" ; echo -e "begin\ntype=cymru" > $tempdir/addr.list
grep -sEo "$REGEX_IP4" $s | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n -u  >> $tempdir/addr.list; echo "end" >> $tempdir/addr.list
${PATH_ncat} whois.pwhois.org 43 < $tempdir/addr.list > $tempdir/addr.txt
cat $tempdir/addr.txt  | sed '/Bulk mode; one IP/d' | sed '/ORG NAME/G' > $tempdir/whois_table.txt
}
#**********************  WHOIS - DOMAIN STATUS  ***********************
f_DOMAIN_STATUS(){
echo ''; f_HEADLINE "$1  WHOIS STATUS"; echo ''; f_WHOIS_STATUS "$1"
f_HEADLINE "DOMAIN WEBPRESENCE"; echo -e "HOST DNS\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
f_dnsCHAIN "$1"; f_getURLSCAN "$1"; f_urlSCAN_FULL "$1" > $tempdir/uscan_results
[[ -f $tempdir/uscan_results ]] && cat $tempdir/uscan_results > ${outdir}/URLSCAN_$1.txt
}

f_WHOIS_STATUS(){
whois_query=$(f_getDOMAIN "$1"); if [ -n "$whois_query" ]; then
unset whois_ns; [[ -f $tempdir/whois_domain ]] && rm $tempdir/whois_domain; [[ -f $tempdir/whois_dates ]] && rm $tempdir/whois_dates
[[ -f $tempdir/dns_ns ]] && rm $tempdir/dns_ns
if echo $whois_query | grep -q -E "\.jp"; then
timeout 20 whois -h whois.jprs.jp ${whois_query} | sed 's/^ *//' | tee $tempdir/whois_temp > $tempdir/whois_domain
if [[ $(grep -sEac "\[Expires on\]" $tempdir/whois_domain) -eq 0 ]]; then
timeout 20 whois -h whois.jprs.jp ${whois_query}/e | sed 's/^ *//' | tee $tempdir/whois_temp > $tempdir/whois_domain; fi
domain_name=$(grep -E "^\[Domain Name\]" $tempdir/whois_domain | cut -d ']' -f 2- | sed 's/^ *//' | tr [:upper:] [:lower:])
whois_source="whois.jprs.jp"
elif echo $whois_query | grep -q -E "\.de"; then
timeout 20 whois -h whois.denic.de -- "-T dn $whois_query" | sed '/^%/d' | sed 's/^ *//' | sed '/^$/d' |
tee $tempdir/whois_temp > $tempdir/whois_domain
domain_name=$(grep -E "^Domain:" $tempdir/whois_domain | awk '{print $NF}' | tr [:upper:] [:lower:] | head -1 | tr -d ' ')
whois_ns=$(grep -sEai "^Nserver:" $tempdir/whois_domain | cut -d ':' -f 2- | tr -d ' ')
whois_source="whois.denic.de"; else
timeout 30 whois $whois_query | sed '/please/d' | sed '/%/d' | sed '/REDACTED/d' | sed '/for more/d' | sed 's/^[ \t]*//;s/[ \t]*$//' |
sed '/^$/d' | tee $tempdir/whois_temp > $tempdir/whois_domain
if [[ $(grep -Eoc "^Copyright Nominet" $tempdir/whois_domain) -gt 0 ]]; then
domain_name=$(grep -A 1 'Domain name:' $tempdir/whois_domain | tail -1 | tr [:upper:] [:lower:] | tr -d ' '); else 
domain_name=$(grep -sEia -m 1 "^Domain Name:|^Domain:" $tempdir/whois_domain | cut -s -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' |
tr [:upper:] [:lower:] | tr -d ' ' | grep -Eo "\b[a-zA-Z0-9._-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,5}\b"); fi; fi
if [ -n "$domain_name" ]; then
if [[ $(grep -Eoc "^Domain Name:" $tempdir/whois_temp) -gt 1 ]]; then
sed -n '/Domain Name:/,/Domain Name:/p' $tempdir/whois_temp > $tempdir/whois_domain; fi
dnssec=$(grep -sEai "^DNSSEC:" $tempdir/whois_domain | grep -sEi -v "unsigned" | cut -d ':' -f 2- | sed 's/^ *//')
#Processing output depending on TLD
if echo $s | grep -q -E "\.jp"; then
whois_ns=$(grep -sEiw "\[Name Server\]" $tempdir/whois_domain | cut -d ']' -f 2 | sed 's/^ *//' | cut -d ' ' -f 1)
dstate=$(grep -E "^\[State\]" $tempdir/whois_domain | cut -d ']' -f 2- | sed 's/^ *//')
upd=$(grep -E "^\[Last Updated\]" $tempdir/whois_domain | cut -d ']' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | cut -d ' ' -f 1)
ex=$(grep -E "^\[Expires on\]" $tempdir/whois_domain | cut -d ']' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | cut -d ' ' -f 1)
cr=$(grep -E "^\[Created on\]" $tempdir/whois_domain | cut -d ']' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | cut -d ' ' -f 1)
registrant=$(grep -sEa "^\[Registrant\]" $tempdir/whois_domain | cut -d ']' -f 2- | sed 's/^ *//')
organisation=$(grep -sEa -A 3 "Contact Information:" $tempdir/whois_domain | grep -sEa "^\[Name\]" | cut -d ']' -f 2- | sed 's/^ *//')
grep -sEa "\[Name Server\]" $tempdir/whois_domain | cut -d ']' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' > $tempdir/whois_ns; else
if [[ $(grep -Eoc "^Copyright Nominet" $tempdir/whois_domain) -gt 0 ]]; then
whois_ns=$(sed -n '/Name servers:/,/Copyright Nominet/p' $tempdir/whois_domain | grep -sEoi "\b[a-zA-Z0-9._-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,5}\b")
registrar=$(grep -A 1 'Registrar:' $tempdir/whois_domain | tail -1)
ex=$(sed -n '/Relevant dates:/,/Registration status:/p' $tempdir/whois_domain | grep 'Expiry' | cut -d ':' -f 2- | sed 's/^ *//')
upd=$(sed -n '/Relevant dates:/,/Registration status:/p' $tempdir/whois_domain | grep 'updated:' | cut -d ':' -f 2- | sed 's/^ *//')
sed -n '/Name servers:/,/WHOIS lookup/p' $tempdir/whois_domain | cut -d ' ' -f 1 | grep '\.' > $tempdir/whois_ns; else
dstatus=$(grep -sEai -m 1 "^Status:|^Domain Status:|^Registration Status:" $tempdir/whois_domain | cut -d ':' -f 2- |
sed 's/^ *//' | awk -F'https://icann.org' '{print $1}')
dstate=$(grep -sEai -m 1 "^state:" $tempdir/whois_domain | cut -d ':' -f 2- |
sed 's/^ *//' | awk -F'https://icann.org' '{print $1}')
hold=$(grep -sEaiw -m 1 "^hold:" $tempdir/whois_domain | cut -d ':' -f 2- | sed 's/^ *//')
reg_lock=$(grep -sEai -m 1 "^registry-lock:" $tempdir/whois_domain | cut -d ':' -f 2- | sed 's/^ *//')
cr=$(grep -sEai "^Creation Date:|Created:|Registration Date:|^Registered" $tempdir/whois_domain | head -1 | cut -d ':' -f 2 |
sed 's/^ *//' | cut -d 'T' -f 1)
upd=$(grep -sEai "^last-update:|^Updated Date:|^Updated" $tempdir/whois_domain | head -1 | cut -d ':' -f 2 | sed 's/^ *//' | cut -d 'T' -f 1)
changd=$(grep -sEai "^Changed:" $tempdir/whois_domain | head -1 | cut -d ':' -f 2 | sed 's/^ *//' | cut -d 'T' -f 1)
trans=$(grep -sEai "^transferred:" $tempdir/whois_domain | head -1 | cut -d ':' -f 2 | sed 's/^ *//' | cut -d 'T' -f 1)
modif=$(grep -sEai "^modified:|^last modified" $tempdir/whois_domain | head -1 | cut -d ':' -f 2 | sed 's/^ *//' | cut -d 'T' -f 1)
country=$(grep -sEai -m 1 "^Registrant Country:|^Country:" $tempdir/whois_domain | cut -d ':' -f 2- | sed 's/^ *//')
registrar=$(grep -sEai "^Registrar:|^Registrar Name:" $tempdir/whois_domain | head -1 | cut -d ':' -f 2- | sed 's/^ *//')
registrant=$(grep -sEai -m 1 "Registrant:" $tempdir/whois_domain | cut -d ':' -f 2- | sed 's/^ *//')
holder=$(grep -sEaiw -m 1 "^holder:" $tempdir/whois_domain | cut -d ':' -f 2- | sed 's/^ *//')
pers=$(grep -sEai -m 1 "person:" $tempdir/whois_domain | cut -d ':' -f 2- | sed 's/^ *//')
organisation=$(grep -sEai "Organisation:|Organization:|^org:|^owner:|^Company Name:" $tempdir/whois_domain | head -1 |
cut -d ':' -f 2- | sed 's/^ *//')
chin_name=$(grep -sEai "^Company chinese name:" $tempdir/whois_domain | head -1 | cut -d ':' -f 2- | sed 's/^ *//')
owner_c=$(grep -sEai "^owner-c:" $tempdir/whois_domain | head -1 | awk '{print $NF}' | sed 's/^ *//')
responsible=$(grep -sEai "^responsible:" $tempdir/whois_domain | head -1 | cut -d ':' -f 2- | sed 's/^ *//')
admin_c=$(grep -sEia -A 2 "^admin-c:|^admin:|^administrator:" $tempdir/whois_domain | grep -sEai "^role:|^nic-hdl:" |
cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' '; echo '')
role_c=$(grep -sEia -A 2 "^role:" $tempdir/whois_domain | grep -sEai "^role:|^nic-hdl:" | cut -d ':' -f 2- |
sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' '; echo ''); fi; fi
if [ -z "$whois_ns" ]; then
if [[ $(grep -o -c 'VeriSign' $tempdir/whois_temp) -gt 0 ]]; then
whois_source="VeriSign"
whois_ns=$(grep -sEai "^Name Server:" $tempdir/whois_domain | awk '{print $NF}' | tr [:upper:] [:lower:]); else
whois_ns=$(grep -sEaiw "^Name Server:|^Nserver:" $tempdir/whois_domain | grep -sEoi "\b[a-zA-Z0-9._-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,5}\b"); fi; fi
if [ -z "$whois_ns" ]; then
whois_ns=$(grep -sEai -A 10 "NAMESERVERS|Name Servers" $tempdir/whois_domain | grep -sEoi "\b[a-zA-Z0-9._-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,5}\b"); fi
if [ -z "$whois_source" ]; then
whois_source=$(grep -sEoi -m 1  "^source:" $tempdir/whois_domain | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//'); fi
whois_server=$(grep -sEoi "^Registrar WHOIS Server:" $tempdir/whois_domain | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
f_getEMAIL "$tempdir/whois_domain" > $tempdir/dom_poc; grep -sEai "\[Phone\]|phone:|hotline" $tempdir/whois_domain | cut -d ':' -f 2- |
cut -d ']' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | tr -d ' ' | sort -u >> $tempdir/dom_poc
[[ -f $tempdir/dom_poc ]] && whois_contact=$(cat $tempdir/dom_poc | tr '[:space:]' ' ' | fmt -w 80; echo '')
[[ -n "$cr" ]] && echo "Created:$cr" >> $tempdir/whois_dates; [[ -n "$ex" ]] && echo "Expires:$ex" >> $tempdir/whois_dates
[[ -n "$pd" ]] && echo "Paid_until:$pd" >> $tempdir/whois_dates; [[ -n "$changd" ]] && echo "Changed:$changd" >> $tempdir/whois_dates
[[ -n "$upd" ]] && echo "Updated:$upd" >> $tempdir/whois_dates; [[ -n "$modif" ]] && echo "Modified:$modif" >> $tempdir/whois_dates
[[ -n "$dfree" ]] && echo "Free:$dfree" >> $tempdir/whois_dates; [[ -n "$trans" ]] && echo "Transferred:$trans" >> $tempdir/whois_dates
if [ -f $tempdir/whois_dates ]; then
whois_dates=$(cat $tempdir/whois_dates | sed '/^$/d' |  tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/ /  /g' | sed 's/_/ /g' |
sed 's/:/: /g' | sed 's/^ *//'); fi
[[ $domain_enum = "false" ]] && [[ $target_type = "dnsrec" ]] && echo -e "WHOIS STATUS\n\n"
[[ $target_type = "whois_target" ]] && echo '' && f_HEADLINE2 "WHOIS STATUS  -  $(f_toUPPER "$whois_query")\n\n"
echo "Domain:      $domain_name"
[[ -n "$dstatus" ]] && [[ $(grep -Eoc "^Domain Status:" $tempdir/whois_domain) -lt 2 ]] && echo "Status:      $dstatus"
[[ -n "$dstate" ]] && echo "State:       $dstate"; [[ -n "$dhold" ]] && echo "Hold:        $dhold"
[[ -n "$reg_lock" ]] && echo "Reg.-Lock:   $reg_lock"; [[ -n "$dnssec" ]] && echo "Dnssec:      $dnssec"
[[ -n "$country" ]] && echo "Country:     $country"; [[ -n "$whois_dates" ]] && echo "Dates:       $whois_dates"
[[ -n "$registrar" ]] && echo "Registrar:   $registrar"; [[ -n "$registrant" ]] && echo "Registrant:  $registrant"
[[ -n "$pers" ]] && echo "Person:      $pers"; [[ -n "$holder" ]] && echo "Holder:      $holder"
[[ -n "$organisation" ]] && echo "Org:         $organisation $chin_name $owner_c"
[[ -n "$responsible" ]] && echo "Responsible: $responsible"; [[ -n "$admin_c" ]] && echo "Admin:       $admin_c"
[[ -n "$role_c" ]] && echo "Role:        $role_c"; [[ -n "$whois_server" ]] && echo "Whois Srv:   $whois_server"
[[ -n "$whois_source" ]] &&  echo "Source:      $whois_source" 
[[ $(echo "$whois_contact" | wc -w) -gt 1 ]] && [[ $(echo "$whois_contact" | wc -w) -lt 4 ]] && echo "Contact:     $whois_contact"
[[ $(echo "$whois_contact" | wc -w) -gt 1 ]] && [[ $(echo "$whois_contact" | wc -w) -gt 3 ]] && echo -e "\n\nCONTACT\n\n$whois_contact"
if [[ $(grep -Eoc "^Domain Status:" $tempdir/whois_domain) -gt 1 ]]; then
echo -e "\n\nDOMAIN STATUS\n"; grep -E "^Domain Status:" $tempdir/whois_domain | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' |
awk '{print $1}' | sort -u | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -s -w 75; echo ''; else
[[ $target_type = "whois_target" ]] && echo ''; fi
echo -e "\nNAME SERVERS\n"; if [ -n "$whois_ns" ]; then
ns_sorted=$(echo "$whois_ns" | sed 's/^[ \t]*//;s/[ \t]*$//' | tr [:upper:] [:lower:] | sort -uV); echo "$ns_sorted" > $tempdir/whois_ns
echo "$ns_sorted" | tr '[:space:]' ' ' | sed 's/ /  /g'; echo ''
dig @1.1.1.1 +short ns $whois_query | rev | cut -c 2- | rev | grep -v 'root-servers.net' | tr -d ' ' | sort -uV  > $tempdir/dns_ns
if ! [ -f $tempdir/dns_ns ]; then
#Comparing whois name servers with actual DNS resource records
echo -e "\nERROR retrieving DNS NS resource records!!!\n"; else
[[ -f $tempdir/whois_ns ]] && [[ -f $tempdir/dns_ns ]] && diff_ns=$(diff -q  $tempdir/whois_ns $tempdir/dns_ns)
if [ -n "$diff_ns" ]; then
print_ns=$(cat $tempdir/dns_ns | tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/ /  /g')
echo -e "\n! WARNING - Name Servers provided in whois do NOT match DNS records !\n\n"
echo -e "NS RECORDS\n\n$print_ns\n"; fi; rm $tempdir/dns_ns; fi
#Printing DNS info for option [w5]
if [ $target_type = "whois_target" ]; then
ns_soa=$(dig @1.1.1.1 soa +noall +answer +noclass +nottlid $domain_name | grep 'SOA' | awk '{print $3,$4,$5}')
echo -e "\n\nSOA\n\n$ns_soa\n"; echo -e "\nDOMAIN HOSTS\n"
print4=$(f_printADDR "$(dig @9.9.9.9 +short $domain_name  | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')")
print6=$(f_printADDR "$(dig @9.9.9.9 aaaa +short $domain_name  | grep ':' | sort -u)")
[[ -n "$print4" ]] && echo -e "$print4" | sed 's/ /  /g' | sed G | tee -a "$tempdir/domains_ipv4"
[[ -n "$print6" ]] && echo -e "$print6" | sed 's/ /  /g' | sed G; fi; else 
echo -e "Error retrieving whois information about domain name servers\n"; fi
if [[ $(grep -Eoc "^Copyright Nominet" $tempdir/whois_domain) -gt 0 ]]; then
echo ''; sed -n '/Copyright Nominet/,$p' $tempdir/whois_domain; fi; else
echo -e "\nERROR getting results for $whois_query\n"; fi; else
echo -e "\nERROR - Invalid domain or host name supplied\n"; fi
}

#-------------------------------  BOGON DETECTION -------------------------------

f_BOGON(){
unset bogon; unset bogon_pfx; unset bogon_type
query=$(echo $1 | cut -d '/' -f 1 | cut -d '-' -f 1 | tr -d ' ')
if [[ $query =~ $REGEX_IP46 ]]; then
if [[ $query =~ $REGEX_IP4 ]]; then
rev=$(awk -F'.' '{printf $4 "." $3 "." $2 "." $1}' <<< $query)
check_bogon=$(dig @1.1.1.1 +short ${rev}.v4.fullbogons.cymru.com TXT | tr -d '\"' | sed 's/^ *//' | tr -d ' '); else
rev=$(dig @1.1.1.1 +noall +question -x $query | cut -d ' ' -f 1 | sed 's/.ip6.arpa.//' | tr -d ';' | tr -d ' ')
check_bogon=$(dig @1.1.1.1 +short ${rev}.v6.fullbogons.cymru.com TXT | tr -d '\"' | sed 's/^ *//' | tr -d ' '); fi
if [[ -n "$check_bogon" ]]; then
bogon="TRUE"; bogon_pfx=$(echo $check_bogon | tr -d '"' | tr -d ' ')
[[ $bogon_pfx = "192.0.2.0/24" ]] && bogon_type="Reserved (TEST-NET-1)"
[[ $bogon_pfx = "198.51.100.0/24 " ]] && bogon_type="Reserved (TEST-NET-2)"
[[ $bogon_pfx = "203.0.113.0/24" ]] && bogon_type="Reserved (TEST-NET-3)"
[[ $bogon_pfx = "100.64.0.0/10" ]] && bogon_type="Carrier grade NAT"
[[ $bogon_pfx = "127.0.0.0/8" ]] && bogon_type="Loopback"
[[ $bogon_pfx = "233.252.0.0/24" ]] && bogon_type="Reserved (MCAST-TEST-NET)"
[[ $bogon_pfx = "192.88.99.0/24" ]] && bogon_type="Reserved (former IPv6 to IPv4 relay)"
[[ $bogon_pfx = "198.18.0.0/15" ]] && bogon_type="Reserved (network benchmark testing)"
[[ $bogon_pfx = "10.0.0.0/8" ]] && bogon_type="RFC1918"
[[ $bogon_pfx = "192.168.0.0/16" ]] && bogon_type="RFC1918"
[[ $bogon_pfx = "224.0.0.0/4 " ]] && bogon_type="IPv4 multicast"
[[ $bogon_pfx = "240.0.0.0/4" ]] && bogon_type="Reserved (future use)"
[[ $bogon_pfx = "169.254.0.0/16" ]] && bogon_type="Link local (APIPA)"
[[ $bogon_pfx = "172.16.0.0" ]] && bogon_type="RFC1918"
[[ $bogon_pfx = "fc00::/7" ]] && bogon_type="Private address space (unique local)"
[[ $bogon_pfx = "fe80::/10" ]] && bogon_type="Link local"
[[ $bogon_pfx = "2001:0002::/48" ]] && bogon_type="Reserved (network benchmark testing)"
[[ $bogon_pfx = "2001:0010::/28" ]] && bogon_type="Reserved (Orchid)"
[[ $bogon_pfx = "2001:db8::/32" ]] && bogon_type="Reserved (documentation)"
[[ $bogon_pfx = "::1/128" ]] && bogon_type="Loopback"; else
bogon="FALSE"; fi; fi; export bogon; export bogon_pfx; export bogon_type
}
f_BOGON_HEADER(){
local s="$*"; f_BOGON "${s}"; if [ $bogon = "TRUE" ]; then
[[ ${s} =~ $REGEX_IP4 ]] && ip_type=$(ipcalc -b -n ${s} | grep -E "Hosts/Net" | awk '{print $3,$4,$5,$6}') || ip_type=$(f_IPV6_INFO "${s}")
f_Long; if [ $target_type = "hop" ]; then
echo -e "HOP $hop_count | $s | BOGON ! | PREFIX: $bogon_pfx\n\nTYPE:  $ip_type $bogon_type"; else
echo -e " $s ! BOGON ! PREFIX: $bogon_pfx\n\n TYPE:  $ip_type $bogon_type"; fi; f_Long; fi
}

#-------------------------------  IP REPUTATION  -------------------------------
f_IP_REPUTATION(){
echo $1 > $tempdir/bl_check
[[ $target_type = "dnsrec" ]] || echo -e "\nIP REPUTATION\n"
[[ $target_type = "default" ]] || [[ $target_type = "web" ]] && f_GREY_NOISE "$1"
f_IPQS "$1"; f_PROJECT_HONEYPOT "$1"; f_ISC "$1"; f_STOP_FSPAM "$1"
f_BLOCKLIST_CHECK "$tempdir/bl_check"
if [[ -f $tempdir/attacks ]] && [[ $(wc -l < $tempdir/attacks) -gt 2 ]]; then
echo -e "\n\n! RECENT INCIDENTS (SOURCE: SANS INTERNET STORM CENTER)\n"; tail -50 $tempdir/attacks; rm $tempdir/attacks; fi
[[ $target_type = "dnsrec" ]] || [[ $target_type = "hop" ]] && echo -e "\n___________________________________________________\n"
}
f_BLOCKLISTS(){
rev=$(echo $1 | awk -F'.' '{printf $4 "." $3 "." $2 "." $1}')
for i in $blocklists; do
in_list="$(dig @1.1.1.1 +short -t a ${rev}.${i}.)"
if [[ $in_list ]]; then
[[ $target_type = "net" ]] && echo -e "; $i ($in_list)" || echo -e "; $i"; else
echo -e "$i"; fi; done
}
f_BLOCKLIST_CHECK(){
local s="$*"
for i in $(sort -uV $s) ; do
bl_entries=$(f_BLOCKLISTS "$i" | grep ';')
if [ -n "$bl_entries" ]; then
print_entries=$(echo "$bl_entries" | tr -d ';' | tr '[:space:]' ' '; echo '')
if [ $target_type = "net" ]; then
echo -e "\n!!! $i !!! \n"; echo -e "\n\n$i\n" >> $tempdir/listings; echo "$print_entries" | tee -a $tempdir/listings; else
if [[ $(echo "$print_entries" | wc -w) -gt 2 ]]; then
if [ $target_type = "web " ] || [ $target_type = "default " ]; then
echo -e "\n\n! DNS Blocklists:\n\n $print_entries"; else
echo -e "\n\n! DNS Blocklists [$i]:\n\n $print_entries"; fi; else
if [ $target_type = "web " ] || [ $target_type = "default " ]; then
echo -e "\n! DNS Blocklists:    $print_entries"; else
echo -e "\n! DNS Blocklists:     [$i] $print_entries"; fi; fi; fi; else
[[ $target_type = "net" ]] && echo -e "+ $i  OK\n" || echo -e "\n+ DNS Blocklists:     Not listed [$i]"; fi; done
}
f_GREY_NOISE(){
curl -m 10 -sL "https://api.greynoise.io/v3/community/$1" > $tempdir/gn.json
if [ -f $tempdir/gn.json ]; then
gn_ip=$(jq -r '.ip' $tempdir/gn.json); gn_mssg=$(jq -r '.message' $tempdir/gn.json)
gn_lseen=$(jq -r '.last_seen' $tempdir/gn.json | sed '/null/d')
if [ -n "$gn_lseen" ]; then
gn_noise=$(jq -r '.noise' $tempdir/gn.json | sed 's/true/Port Scanner/' | sed 's/false/Noise: None/')
gn_class=$(jq -r '.classification' $tempdir/gn.json); gn_riot=$(jq -r '.riot' $tempdir/gn.json)
[[ $gn_riot = "true" ]] && riot="| Rule-it-out: true" || riot=''
echo -e "\n! GreyNoise:          $gn_noise | Classification: $gn_class | Last: $gn_lseen $riot"; else
message_out=$(echo "$gn_mssg" | sed 's/IP not observed scanning the internet or contained in RIOT data set./Not observed scanning the internet/')
echo -e "\n+ GreyNoise:          $message_out"; fi; rm $tempdir/gn.json; fi
}
f_IPQS(){
if [[ -n "$api_key_iqs" ]]; then
curl -m 10 -sL "https://ipqualityscore.com/api/json/ip/$api_key_iqs/$1" > $tempdir/ipqs.json
ipqs_success=$(jq -r '.success' $tempdir/ipqs.json | grep -o 'true')
if [ -n "$ipqs_success" ]; then
fraud_score=$(jq -r '.fraud_score' $tempdir/ipqs.json); recent_abuse=$(jq -r '.recent_abuse' $tempdir/ipqs.json)
if [[ $fraud_score -lt 41 ]]; then
ipqs_class="Good"; ipqs_marking="+"
elif [[ $fraud_score -lt 76 ]]; then
ipqs_class="Suspicious"; ipqs_marking="!"; else
ipqs_class="Poor"; ipqs_marking="!"; fi
jq -r '.bot_status' $tempdir/ipqs.json | grep -o 'true' | sed 's/true/Bot/' > $tempdir/ipqs_descr
jq -r '.is_crawler' $tempdir/ipqs.json | grep -o 'true' | sed 's/true/Crawler/' >> $tempdir/ipqs_descr
jq -r '.vpn' $tempdir/ipqs.json | grep -o 'true' | sed 's/true/VPN/' >> $tempdir/ipqs_descr
jq -r '.proxy' $tempdir/ipqs.json | grep -o 'true' | sed 's/true/Proxy/' >> $tempdir/ipqs_descr
jq -r '.mobile' $tempdir/ipqs.json | grep -o 'true' | sed 's/true/Mobile/' >> $tempdir/ipqs_descr
jq -r '.active_tor' $tempdir/ipqs.json | grep -o 'true' | sed 's/true/Tor/' >> $tempdir/ipqs_descr
[[ -f $tempdir/ipqs_descr ]] && ipqs_descr="| $(cat $tempdir/ipqs_descr | tr '[:space:]' ' '; echo '')"
echo -e "\n$ipqs_marking IPQualityScore:     $fraud_score ($ipqs_class) | Recent abuse: $recent_abuse $ipqs_descr"; else
echo -e "\n+ IPQualityScore:      No response"; fi; else 
echo -e "\n+ IPQualityScore:      API key required (see help)"; fi
}
f_ISC(){
curl -s "https://isc.sans.edu/api/ip/$1?json" > $tempdir/iscip.json
if [ -f $tempdir/iscip.json ]; then
ip_num=$(jq -r '.ip.number' $tempdir/iscip.json)
incidents=$(jq -r '.ip.count?' $tempdir/iscip.json | sed '/null/d')
if [ -n "$incidents" ]; then
ip_attacks=$(jq -r '.ip.attacks?' $tempdir/iscip.json); ip_mindate=$(jq -r '.ip.mindate?' $tempdir/iscip.json); ip_maxdate=$(jq -r '.ip.maxdate?' $tempdir/iscip.json)
echo -e "\n! SANS ISC:           Incidents: $incidents | Attacks: $ip_attacks  ($ip_mindate - $ip_maxdate)"
curl -s "https://isc.sans.edu/api/ipdetails/$1?json" > $tempdir/ipdetails.json
jq -r '.[] | { Date: .date, Time: .time, SourcePort: .sourceport, TargetPort: .targetport, Protocol: .protocol}' $tempdir/ipdetails.json |
tr -d '},\"{' | sed 's/^ *//' | sed '/^$/d' | sed 's/null/?/' | tr '[:space:]' ' ' | sed 's/Date: /\n/g' | sed 's/Time:/-/' |
sed 's/SourcePort:/| Src Port:/' | sed 's/TargetPort:/| Target Port:/' | sed 's/Protocol:/| Protocol:/' | sed 's/Protocol: 6/Protocol: TCP/' |
sed 's/Protocol: 17/Protocol: UDP/' | sed 's/^/  /' > $tempdir/attacks; echo '' >> $tempdir/attacks; else
echo -e "\n+ SANS ISC:           No results for $ip_num"; fi; rm $tempdir/iscip.json; fi
}
f_PROJECT_HONEYPOT(){
if [ -n "$api_key_honeypot" ]; then
res=$(dig @1.1.1.1 +short ${api_key_honeypot}.$(echo $1 | awk -F'.' '{printf $4 "." $3 "." $2 "." $1}').dnsbl.httpbl.org)
if [[ -n "$res" ]]; then
ph_lseen=$(echo "$res" | awk -F'.' '{print $2}'); ph_score=$(echo "$res" | awk -F'.' '{print $3}')
type=$(echo "$res" | awk -F'.' '{print $4}'); [[ $type = "0" ]] && agent_cat="Search Engine"
[[ $type = "1" ]] && agent_cat="Suspicious"; [[ $type = "2" ]] && agent_cat="Harvester"
[[ $type = "4" ]] && agent_cat="Comment Spammer"; [[ $type = "5" ]] && agent_cat="Suspicious/Comment Spammer"
[[ $type = "6" ]] && agent_cat="Harvester/Comment Spammer"; [[ -z "$agent_cat" ]] && agent_cat="Category: unknown"
if [ $type = "0" ]; then
if [ $score = "0" ]; then
seng="Undocumented"
elif [ $score = "3" ]; then
seng="Baidu"
elif [ $score = "5" ]; then
seng="Google"
elif [ $score = "8" ]; then
seng="Yahoo"; else
seng="Other"; fi
echo -e "\n+ Project Honeypot:   $agent_cat | Agent: $seng | Last: $ph_lseen day(s) ago"; else
echo -e "\n! Project Honeypot:   $agent_cat | Threat score: $ph_score | Last: $ph_lseen day(s) ago"; fi; else
echo -e "\n+ Project Honeypot:   No results for $1"; fi; else
echo -e "\n+ Project Honeypot:   API key required (see help)"; fi
}
f_STOP_FSPAM(){
curl -s "http://api.stopforumspam.org/api?ip=$1&json&badtorexit" > $tempdir/fs.json
ip_value=$(jq -r '.ip.value' $tempdir/fs.json)
if [ -n "$ip_value" ]; then
fspam_lseen=$(jq -r '.ip.lastseen' $tempdir/fs.json | sed '/null/d')
freq=$(jq -r '.ip.frequency' $tempdir/fs.json); fspam_geo=$(jq -r '.ip.country' $tempdir/fs.json | tr [:lower:] [:upper:])
fspam_active=$(jq -r '.ip.appears' $tempdir/fs.json | sed 's/1/active/' | sed 's/0/Appears: 0/')
if  [ -n "$fspam_lseen" ]; then
conf=$(jq -r '.ip.confidence' $tempdir/fs.json)
torex=$(jq -r '.ip.torexit' $tempdir/fs.json | grep -o 'true' | sed 's/true/| Bad Tor exit/')
echo -e "\n! Stop Forum SPAM:    $conf confidence | $fspam_active (Last: $fspam_lseen) | Freq: $freq | Geo: $fspam_geo $torex"; else
echo -e "\n+ Stop Forum SPAM:    $fspam_active | Freq: $freq | Geo: $fspam_geo"; fi; else
echo -e "\n+ Stop Forum SPAM:    No response"; fi
}
f_TOR(){
is_tor=$(dig @1.1.1.1 +short -t a $(echo $1 | awk -F'.' '{printf $4 "." $3 "." $2 "." $1}').tor.dan.me.uk.)
[[ -n "$is_tor" ]] && echo "TOR: true" || echo "TOR: false"
}

#-------------------------------  HOST INFORMATION  -------------------------------

#**********************  GET HOST INFO  ***********************
f_getHostInfo(){
[[ -f $tempdir/abx ]] && rm $tempdir/abx; [[ -f $tempdir/shodan.json ]] && rm $tempdir/shodan.json
[[ -f $tempdir/chain.json ]] && rm $tempdir/chain.json; f_getRIR "$1"; f_GEO "$1"; f_getABUSE_C "$1"
[[ $1 =~ $REGEX_IP4 ]] && [[ $target_type != "hop" ]] && curl -s -m 20 "https://internetdb.shodan.io/$1" > $tempdir/shodan.json
if [ $target_type = "default" ] || [ $target_type = "hop" ]; then
if [ $target_type = "default" ]; then
curl -s --location --request GET "https://stat.ripe.net/data/dns-chain/data.json?resource=$1" > $tempdir/chain.json; fi
timeout 30 whois -h whois.pwhois.org $1 > $tempdir/pwhois
[[ $target_type = "default" ]] && f_get_RIPESTAT_WHOIS "$1"; fi
}
f_GEO(){
[[ -f $tempdir/geo.json ]] && rm $tempdir/geo.json
curl -s -m 7 "http://ip-api.com/json/$1?fields=54750751" > $tempdir/geo.json
if [ $(jq -r '.status' $tempdir/geo.json) = "success" ]; then
city=$(jq -r '.city' $tempdir/geo.json)
geo_country=$(jq -r '.country' $tempdir/geo.json | sed 's/United States/US/' | sed 's/United Kingdom/UK/')
[[ $target_type = "default" ]] && regio=$(jq -r '.regionName' $tempdir/geo.json) || regio=$(jq -r '.region' $tempdir/geo.json)
[[ "$regio" = "$city" ]] && echo "$city, $geo_country" > $tempdir/geo || echo "$city, $regio, $geo_country" > $tempdir/geo; fi
}
f_getABUSE_C(){
if [ $target_type = "default" ] && [ $rir = "lacnic" ]; then
whois -h whois.lacnic.net $1 > $tempdir/whois; f_printLACNIC_ABUSE_C "$tempdir/whois" > $tempdir/abx; else
if [ $rir != "lacnic" ]; then 
if [[ $1 =~ $REGEX_IP4 ]]; then
rev=$(awk -F'.' '{printf $4 "." $3 "." $2 "." $1}' <<<$1); else
rev=$(dig @1.1.1.1 +noall +question -x $1 | cut -d ' ' -f 1 | sed 's/.ip6.arpa.//' | tr -d ';' | tr -d ' '); fi 
dig @1.1.1.1 +short $rev.abuse-contacts.abusix.zone txt | grep -v 'lacnic' | tr -d '"' > $tempdir/abx
if [ ! -f $tempdir/abx ] || [[ $(grep -c "$REGEX_EMAIL" $tempdir/abx) -eq 0 ]]; then 
curl -m 5 -s "https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=$1" | jq -r '.data.abuse_contacts[]?' > $tempdir/abx; fi; fi; fi
}
f_getCPES(){
if [ -f $tempdir/shodan.json ]; then
cpes=$(jq -r '.cpes[]?' $tempdir/shodan.json | sed 's/^cpe:\///' | sort | tr '[:space:]' ' ' | sed 's/ /  /g' |
sed 's/^ *//'); [[ -n "$cpes" ]] && echo "$cpes"; fi
}
f_getCVES(){
if [ -f $tempdir/shodan.json ]; then
cves=$(jq -r '.vulns[]?' $tempdir/shodan.json); [[ -n "$cves" ]] && echo "$cves" | tr '[:space:]' ' ' | fmt -w 70; fi
}
f_getHOSTNAMES(){
[[ -f $tempdir/hostnames ]] && rm $tempdir/hostnames
[[ -f $tempdir/shodan.json ]] && jq -r '.hostnames[]?' $tempdir/shodan.json | sort > $tempdir/hostnames
if [ -f $tempdir/hostnames ] && [[ $(cat $tempdir/hostnames | wc -w) -gt 0 ]]; then
if [ $target_type = "net" ] && [ $target_type = "other" ]; then
head -15 $tempdir/hostnames | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/ /  /g' | sed 's/^ *//' | fmt -w 100; echo ''; else
cat $tempdir/hostnames | tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/ /  /g' | sed 's/^ *//' | fmt -w 70; echo ''; fi; fi
}
f_getHOST_SERVICES(){
[[ -f $tempdir/tags ]] && rm $tempdir/tags; unset detected_ports; unset print_ports; unset shodan_cpes
if [[ $1 =~ $REGEX_IP4 ]]; then
if [ -f $tempdir/shodan.json ]; then
detected_ports=$(jq -r '.ports[]?' $tempdir/shodan.json | grep [0-9])
if [ -n "$detected_ports" ]; then
print_ports=$(echo "$detected_ports" | tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//')
echo "$detected_ports" >> $tempdir/detected_ports; [[ $target_type = "default" ]] || shodan_cpes=$(f_getCPES); else
print_ports="unknown"; fi; jq -r '.tags[]?' $tempdir/shodan.json > $tempdir/tags;
f_TOR "$1" | grep 'true' | grep -o 'TOR' >> $tempdir/tags; fi; else
v6_info=$(f_IPV6_INFO "$1"); [[ -n "$v6_info" ]] && echo "$v6_info" > $tempdir/tags; fi
if [ -f $tempdir/geo.json ]; then 
jq -r '.proxy' $tempdir/geo.json | grep -o 'true' | sed 's/true/proxy/' >> $tempdir/tags
jq -r '.mobile' $tempdir/geo.json | grep -o 'true' | sed 's/true/mobile/' >> $tempdir/tags
jq -r '.hosting' $tempdir/geo.json | grep -o 'true' | sed 's/true/hosting/' >> $tempdir/tags; fi 
[[ -f $tempdir/tags ]] && [[ $(wc -w < $tempdir/tags) -gt 0 ]] && sort -u $tempdir/tags > $tempdir/addr_info
if [ -n "$print_ports" ]; then
[[ -f $tempdir/addr_info ]] && echo "| Ports: $print_ports" >> $tempdir/addr_info || echo "Ports: $print_ports" > $tempdir/addr_info; fi
if [[ $1 =~ $REGEX_IP4 ]] && [ $target_type != "default" ] && [ -n "$shodan_cpes" ]; then
print_cpes=$(echo "$shodan_cpes" | tr '[:space:]' ' ')
[[ $(wc -w <<<$print_cpes) -gt 2 ]] && echo "___$print_cpes" >> $tempdir/addr_info || echo "| $print_cpes" >> $tempdir/addr_info; fi
[[ -f $tempdir/addr_info ]] && cat  $tempdir/addr_info | tr '[:space:]' ' ' | sed 's/___/\n\n/g' | sed 's/^ *//' && echo '' && rm $tempdir/addr_info
}
f_IPV6_INFO(){
local h="$*"; [[ -f $tempdir/v6info ]] && rm $tempdir/v6info
${PATH_nmap} -6 -sn -Pn $h --script address-info.nse 2>/dev/null | grep -E "^\|" | tr -d '|_' | sed 's/^ *//' |
grep -E "address:|IPv4|IPv6|MAC|manuf|ISATAP" | sed 's/IPv4 address:/| IPv4:/' | sed 's/MAC address: /| MAC/' |
sed 's/IPv6 [Aa]ddress:/IPv6 Addr/' | sed 's/IPv6 EUI-64: /EUI-64/' | sed 's/^[ \t]*//;s/[ \t]*$//' |
tr '[:space:]' ' ' | sed 's/MAC address:/MAC:/' > $tempdir/v6info
[[ -f $tempdir/v6info ]] && cat $tempdir/v6info | tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//' && echo ''
}
#**********************  PRINT HOST INFO  ***********************
f_CVES(){
[[ -f $tempdir/shodan.json ]] && rm $tempdir/shodan.json
curl -s -m 5 "https://internetdb.shodan.io/$1" > $tempdir/shodan.json
if [ -f $tempdir/shodan.json ]; then
[[ -f $tempdir/tags ]] && rm $tempdir/tags
unset print_tags; unset shodan_ports; unset shodan_cves; unset vulners
shodan_ports=$(jq -r '.ports[]?' $tempdir/shodan.json | sed '/null/d')
if [ -n "$shodan_ports" ]; then
echo "$shodan_ports" >> $tempdir/net_ports; hostn=$(f_getHOSTNAMES); f_TOR "$1" | grep 'true' | grep -o 'TOR' > $tempdir/tags
print_ports=$(echo "$shodan_ports" | tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//')
jq -r '.tags[]?' $tempdir/shodan.json | sed 's/cloud/Cloud/' | sed 's/vpn/VPN/' |
sed 's/starttls/StartTLS/' | sed 's/database/Database/' | sort -u >> $tempdir/tags
shodan_cpes=$(f_getCPES) && shodan_cves=$(f_getCVES)
[[ -n "$shodan_cves" ]] && vulners="$shodan_cves" || vulners="-"
[[ -n "$print_tags" ]] && echo -e "\n\n>  $1  ($print_tags)" || echo -e "\n\n>  $1"
if [ -n "$shodan_cpes" ]; then
if [[ $(wc -w <<<$shodan_cpes) -lt 4 ]]; then
echo -e "\n+  Ports:  $print_ports  | CPEs: $shodan_cpes"; else
echo -e "\n+  Ports:  $print_ports"; echo -e "\n+  CPEs:   $shodan_cpes"; fi; else 
echo -e "\n+  Ports:  $print_ports"; fi
[[ -n "$hostn" ]] && echo -e "\n$hostn" | sed 's/^/   /'
[[ -n "$shodan_cves" ]] && echo -e "\n   ! VULNS !\n" && echo -e "$vulners" | sed 's/^/   /'; echo ''; else
[[ $target_type != "net" ]] && echo -e "\n\n>  $1\n\n!  No data for open ports, services & CVEs\n"; fi; else
[[ $target_type != "net" ]] && echo -e "\n\n>  $1\n\n   No response\n"; fi
}

f_HOP(){
unset tor_node; unset tor_message; echo ''; f_BOGON "$1"
if [ $bogon = "TRUE" ]; then
f_BOGON_HEADER "$1"; else
[[ -f $tempdir/whois_records ]] && rm $tempdir/whois_records;
[[ -f $tempdir/pwhois ]] && rm $tempdir/pwhois; f_getHostInfo "$1"
if [[ $(grep -sEc "^Origin-AS:" $tempdir/pwhois) -gt 0 ]]; then
prefix=$(grep -sE -m 1 "^Prefix:" $tempdir/pwhois | awk '{print $NF}' | tr -d ' ')
asn=$(grep -sE -m 1 "^Origin-AS:" $tempdir/pwhois | awk '{print $NF}' | tr -d ' ')
curl -s -m 5 --location --request GET "https://stat.ripe.net/data/rpki-validation/data.json?resource=$asn&prefix=$prefix" > $tempdir/rpki.json
rpki_status=$(jq -r '.data.status?' $tempdir/rpki.json); mobile_net=$(jq -r '.mobile' $tempdir/geo.json | grep 'true' | sed 's/true/ | MOBILE/')
[[ $1 =~ $REGEX_IP4 ]] && tor_node=$(f_TOR "$1" | grep 'true') || tor_node=''
[[ -n "$tor_node" ]] && tor_message="| TOR !"; [[ $rir = "lacnic" ]] || f_getABUSE_C "$1"
f_Long; if [ -n "$hop_count" ]; then
echo "HOP $hop_count |  $1  | AS $asn | ROA: $rpki_status | RTT: $rtt $mobile_net $tor_node"; else
echo "HOP $hop_count |  $1  | AS $asn | ROA: $rpki_status  $mobile_net $tor_node"; fi; f_Long
[[ $rir = "lacnic" ]] && echo -e "Geo: $(cat $tempdir/geo)  |  ROA: $rpki_status" || f_printABUSE_C; f_getHostRevDNS "$1"
if ! [[ $1 =~ $REGEX_IP4 ]]; then
v6_info=$(f_IPV6_INFO "$1"); [[ -n "$v6_info" ]] && echo -e "\nAddr.Type:     $v6_info"; fi; #f_getORG
org=$(jq -r '.org' $tempdir/geo.json); [[ -z "$org" ]] && org=$(jq -r '.isp' $tempdir/geo.json)
echo -e "\nORG:          $org"
if [ $rir = "lacnic" ]; then
echo -e "\nBGP:          *>  $prefix  (LACNIC)" ; else
netname=$(grep -sE -m 1 "^Net-Name:" $tempdir/pwhois | awk '{print $NF}' |  tr -d ' ')
echo -e "\nBGP:          *>  $prefix  | $netname | $(f_toUPPER "$rir")"; fi
vis=$(f_VIS "$prefix"); echo -e "\nRIS:          $vis"; f_getASNAME "$asn"; else 
f_get_RIPESTAT_WHOIS "$1"; ix_host=$(f_IX_HOST "$1"); if [ -n "$ix_host" ]; then
echo "$ix_host"; [[ $rir = "lacnic" ]] && whois -h whois.lacnic.net $1 > $tempdir/whois; echo ''; f_NET_SHORT "$1"; fi; fi; fi
}
f_HOST_DEFAULT(){
echo ''; f_BOGON "$1"; if [ $bogon = "TRUE" ] ; then
f_BOGON_HEADER "$1"; else
unset rev_dns; f_getHostInfo "$1"; asn=$(grep -sE -m 1 "^Origin-AS:" $tempdir/pwhois | awk '{print $NF}' | tr -d ' ')
auth_ns=$(jq -r '.data.authoritative_nameservers[]?' $tempdir/chain.json | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -w 70)
[[ -z "$asn" ]] && ix_host=$(f_IX_HOST "$1") && [[ -n "$ix_host" ]] && echo "$ix_host" && f_getHostRevDNS "$1" && f_NET_SHORT "$1"
if [ -z "$ix_host" ]; then
geo_cc=$(jq -r '.countryCode' $tempdir/geo.json); offset=$(($(jq -r '.offset' $tempdir/geo.json) / 3600))
service_info=$(f_getHOST_SERVICES "$1"); if [[ $1 =~ $REGEX_IP4 ]]; then
shodan_cpes=$(f_getCPES); shodan_cves=$(f_getCVES); hostn=$(f_getHOSTNAMES); fi
f_Long; echo "[+]  $1  |  $geo_cc (UTC $offset H)  |  $file_date"; f_Long; f_printABUSE_C; f_getHostRevDNS "$1"
[[ -n "$service_info" ]] && echo -e "\nServices:     $service_info"
if [[ $1 =~ $REGEX_IP4 ]]; then
[[ -n "$shodan_cpes" ]] && [[ $(f_countW "$shodan_cpes") -lt 4 ]] && echo -e "\nCPEs:         $shodan_cpes"
[[ -n "$hostn" ]] && [[ $(f_countW "$hostn") -lt 4 ]] && echo -e "\nHostnames:    $hostn"; fi 
echo -e "\n"; f_NET_SHORT "$1"
[[ $rir != "lacnic" ]] && [[ -n "$auth_ns" ]] && f_HEADLINE2 "AUTH NS\n" && echo "$auth_ns"
if [[ $1 =~ $REGEX_IP4 ]]; then
[[ $(f_countW "$shodan_cpes") -gt 3 ]] && f_HEADLINE2 "CPES" && echo -e "$shodan_cpes" | fmt -w 70 | sed G
[[ -n "$shodan_cves" ]] && f_HEADLINE2 "VULNERS\n" && echo -e "$shodan_cves\n\n(SOURCE: SHODAN)"
[[ $(f_countW "$hostn") -gt 3 ]] && f_HEADLINE2 "HOSTNAMES\n" && echo "$hostn" | sed G
[[ $threat_enum = "true" ]] && f_Long && f_IP_REPUTATION "$1"; fi; fi; fi
}
f_HOST_SHORT(){
f_BOGON "$1"; if [ $bogon = "TRUE" ]; then
echo ''; f_BOGON_HEADER "$1"; else
unset shodan_cpes; unset shodan_cves; unset hostnames; f_getHostInfo "$1"
service_info=$(f_getHOST_SERVICES "$1"); [[ $1 =~ $REGEX_IP4 ]] && shodan_cves=$(f_getCVES)
[[ -f $tempdir/abx ]] && abu=$(f_getEMAIL "$tempdir/abx" | tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//')
[[ $domain_enum = "true" ]] && echo ''; [[ $target_type = "dnsrec" ]] || route_info=$(f_ROUTE "$1")
offset=$(($(jq -r '.offset' $tempdir/geo.json) / 3600)); org=$(jq -r '.org' $tempdir/geo.json)
[[ -z "$org" ]] && org=$(jq -r '.isp' $tempdir/geo.json); ip_geo=$(cat $tempdir/geo)
[[ $target_type = "web" ]] && f_HEADLINE2 "$1\n\n" || echo -e "\n$1\n"
[[ -n "$abu" ]] && echo -e "$ip_geo (UTC $offset) | $org | $abu\n" || echo -e "$ip_geo (UTC $offset) | $org\n"
if [ $target_type = "dnsrec" ]; then
if [ $domain_enum = "true" ]; then
ptr_rec=$(f_getHostRevDNS "$1"); [[ -n "$ptr_rec" ]] && echo -e "$ptr_rec\n"; fi; else
echo -e "$route_info\n"; fi
if ! [[ $1 =~ $REGEX_IP4 ]]; then
[[ $(wc -w <<<$service_info) -gt 0 ]] && echo "Services/Type: $service_info"; else
[[ $target_type = "dnsrec" ]] && echo -e "Services: $service_info" || echo -e "\nSERVICES:\n\n$service_info\n"
if [ $target_type = "web" ]; then
f_Medium; echo -e "VULNERS (SOURCE: SHODAN)\n"
[[ -n "$shodan_cves" ]] && echo -e "\n$shodan_cves" || echo "No CVEs found"; f_Medium
f_IP_REPUTATION "$1"; else
[[ -n "$shodan_cves" ]] && [[ $(wc -w <<<$shodan_cves) -gt 0 ]] && echo -e "\nVULNERS (Shodan):\n\n$shodan_cves\n"; fi; fi; fi
}
f_IX_HOST(){
if [ $rir = "arin" ]; then
ix_lookup=$(jq -r '.data.records[]? | .[] | select (.key=="CIDR") | .value' $tempdir/whois.json | tail -1); else
ix_lookup=$(f_getNET_RANGE "$1"); fi; ixlid=$(grep -m 1 -A 1 "$ix_lookup" ./${file_date}.ix_pfx.txt | tail -1 | tr -d ' ')
if [ -n "$ixlid" ]; then
curl -s "https://www.peeringdb.com/api/ix/${ixlid}" > $tempdir/ixlan.json
f_getABUSE_C "$1"; abuse_mbox=$(sort -u $tempdir/abx | tr '[:space:]' ' ')
ix_name=$(jq -r '.data[0].name' $tempdir/ixlan.json); ix_cc=$(jq -r '.data[0].org.country' $tempdir/ixlan.json)
ix_city=$(jq -r '.data[0].city' $tempdir/ixlan.json); ix_mail=$(jq -r '.data[0].tech_email' $tempdir/ixlan.json)
ix_phone=$(jq -r '.data[0].tech_phone' $tempdir/ixlan.json)
if [ $target_type = "hop" ]; then
echo ''; f_Long; echo "HOP $hop_count | IX ! |  $1  | $ix_name | RTT: $rtt"; f_Long; else
f_Long; echo "[+]  $1  | INTERNET EXCHANGE | $ix_name"; f_Long; fi
echo -e "[@]: $abuse_mbox\n"; echo -e "\nGeo:          $ix_city, $ix_cc"
echo -e "\nContact:      $ix_mail  $ix_phone\n"; fi
}
f_printABUSE_C(){
ip_geo=$(cat $tempdir/geo); abuse_mbox=$(f_getEMAIL "$tempdir/abx" | tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//')
if [[ $(f_countW "$abuse_mbox") -gt 0 ]]; then 
[[ $(f_countW "$abuse_mbox") -gt 2 ]] && echo -e "[@]:  $abuse_mbox\n\nGEO:  $ip_geo\n___\n" || echo -e "[@]:  $abuse_mbox  |  $ip_geo\n___\n"; else
echo -e "[@]:  NA  |  $ip_geo\n___\n"; fi
}

#-------------------------------  NETWORK INFO & NETWORK ENUMERATION -------------------------------

#**********************  BASIC FUNCTIONS & NETWORK WHOIS  ***********************
f_NET_DETAILS(){
local s="$*"; [[ -f $tempdir/maxmind_data ]] && rm $tempdir/maxmind_data
if [ $option_netdetails2 = "1" ] || [ $option_netdetails2 = "3" ]; then
[[ $option_detail = "0" ]] && f_ROUTE_CONS "$s"; f_RELATED "$prefix"; f_NETGEO_MAXMIND "$s"
[[ -f $tempdir/maxmind_data ]] && [[ $(grep -c '|' $tempdir/maxmind_data) -lt 5 ]] && cat $tempdir/maxmind_data; fi
[[ $option_netdetails4 = "1" ]] || [[ $option_netdetails4 = "3" ]] && echo '' && f_NET_RDNS "$s"
[[ $option_netdetails4 = "2" ]] || [[ $option_netdetails4 = "3" ]] && echo '' && f_REV_IP "$s"
[[ $option_netdetails5 = "1" ]] || [[ $option_netdetails5 = "3" ]] && echo '' && f_Long && f_BANNERS "$s"
[[ $option_netdetails5 = "2" ]] || [[ $option_netdetails5 = "3" ]] && f_NET_CVEs "$s"
[[ $psweep = "true" ]] && f_PING_SWEEP "$s"
[[ $option_netdetails2 = "1" ]] || [[ $option_netdetails2 = "3" ]] && f_SUBNETS "$s"
[[ -f $tempdir/maxmind_data ]] && [[ $(grep -c '|' $tempdir/maxmind_data) -gt 4 ]] && cat $tempdir/maxmind_data
if [ $option_detail != "0" ] || [ $rir != "lacnic" ] || [ $rir != "arin" ]; then
if [ $option_netdetails2 = "2" ] || [ $option_netdetails2 = "3" ]; then
if [ $option_detail = "0" ]; then
net_name=$(grep 'name >' $tempdir/tmp_whois | cut -d '>' -f 2 | sed 's/^ *//'); else 
net_name=$(grep -sEai -m 1 "^netname:"  $tempdir/whois | awk '{print $NF}' | tr d ' '); fi
[[ -n "$net_name" ]] && f_RESOURCES_NETNAME "$net_name"; fi; fi
if [ $option_netdetails3 = "1" ] || [ $option_netdetails3 = "3" ]; then
[[ $rir = "ripe" ]] && echo '' && f_HEADLINE2 "REV. DNS LOOKUP ZONES" && f_DELEGATION "$s"; fi
}
f_NET_HEADER(){
echo ''; f_Long; echo -e "NET |  $1  | $nh $file_date"; f_Long
if [ -n "$is_net" ] && [[ $is_net =~ $REGEX_IP4 ]]; then
output_ipcalc=$(${PATH_ipcalc} -b -n $1); hostnum=$(echo "$output_ipcalc" | grep 'Hosts/Net' | awk '{print $2}')
ip_type=$(echo "$output_ipcalc" | grep -E "Hosts/Net" | awk '{print $3,$4,$5,$6}')
netid_bcast=$(echo "$output_ipcalc" | grep -E "Address:|Broadcast" | awk '{print $2}' | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' |
sed 's/^ *//' | awk '{print $1,"-",$2}'); nmask=$(echo "$output_ipcalc" |  grep -E "^Netmask:" | awk '{print $2}' | tr -d ' ')
echo -e "\n$netid_bcast  (Hosts: $hostnum)  $nmask\n"; else
echo ''; fi
if [ $bogon = "TRUE" ]; then
[[ $1 =~ $REGEX_IP4 ]] || v6_type=$(f_IPV6_INFO "$1")
echo -e "! BOGON ! Prefix: $bogon_pfx; type: $ip_type $v6_type\n"; else
[[ $option_detail = "0" ]] && f_NET_SHORT "$1" && f_NET_DETAILS "$1"; fi 
}
f_NET_INFO(){
local s="$*"
net_name=$(grep -sEai -m 1 "^netname:"  $tempdir/whois | awk '{print $NF}' | tr d ' ')
status=$(grep -sEa -m 1 "^status:|^NetType:" $tempdir/whois | cut -d ':' -f 2- | sed 's/^ *//')
net_range=$(grep -sEa -m 1 "inet[6]?num|NetRange:|^in:|^i6:" $tempdir/whois | awk '{print $2 $3 $4}')
org_id=$(grep -sE -m 1 "^organisation:|^org:" $tempdir/whois | awk '{print $NF}' | tr -d ' ')
orgz=$(grep -E -m 1 "^Organization:" $tempdir/whois | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
created=$(grep -E "^RegDate:|^created:" $tempdir/whois | head -1 | cut -d ':' -f 2- | cut -d '-' -f -2 | sed 's/^ *//')
descr=$(grep -sEa -m 1 "^descr:" $tempdir/whois | cut -d ':' -f 2- | sed 's/^ *//' | tr '[:space:]' ' ' ; echo '')
if [ $rir = "arin" ]; then
range_start=$(cut -d '-' -f 1 <<<$net_range)
cidr=$(grep -E -m 1 "^CIDR:" $tempdir/whois | cut -d ' ' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
[[ $(wc -w <<<$cidr) -gt 1 ]] && print_cidr=$(f_printADDR "$cidr")
[[ $(wc -w <<<$cidr) -eq 1 ]] && net_addr="$cidr" || net_addr=''
if [ -n "$net_addr" ]; then
[[ ${range_start} =~ $REGEX_IP4 ]] && net_mask=$(f_ipCALC "$net_addr"); net_geo=$(f_NETGEO "$net_addr"); else
[[ $target_type = "nethandle" ]] && net_geo=$(f_NETGEO "$range_start") || net_geo=$(f_NETGEO "$net_ip"); fi; else
net_addr=$(f_getNET_RANGE "$s")
if [[ $net_addr =~ "/" ]]; then
[[ $net_ip =~ $REGEX_IP4 ]] && net_mask=$(f_ipCALC "$net_addr"); net_geo=$(f_NETGEO "$net_addr"); else
net_geo=$(f_NETGEO "$net_ip"); fi
if [[ $net_ip =~ $REGEX_IP4 ]] && [ $rir = "ripe" ]; then
space_usage_res=$(jq -r '.data.resource?' $tempdir/space_usage.json | sed '/null/d')
if [ -n "$space_usage_res" ] && [[ $space_usage_res =~ "/" ]]; then
net_status=$(echo $status | grep -sEow "SUB-ALLOCATED PA|ASSIGNED PA" | cut -d ' ' -f 1)
if [ -n "$net_status" ]; then
if [ $net_status = "ASSIGNED" ]; then
parent_net=$(jq -r '.data.assignments[0].parent_allocation?' $tempdir/space_usage.json)
elif [ $net_status = "SUB-ALLOCATED" ]; then
parent_net=$(jq -r '.data.allocations[] | .allocation, .status' $tempdir/space_usage.json  | grep -E -B 1 "^ALLOCATED PA"  | head -1); fi
if [ -n "$parent_net" ]; then
parent=$(jq -r '.data.allocations[] | {N: .allocation, A: .asn_name, S: .status}?' $tempdir/space_usage.json | tr -d ']},"{[' |
sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' | sed 's/^ *//' | sed 's/N: /\n/g' | sed 's/A: /(/' | sed 's/S:/)/' |
sed 's/ )/)/' | sed '/)/G' | grep ')' | grep -w "$parent_net" | sed 's/)/) /'; echo ''); fi; fi; fi; fi; fi
if [ $rir = "arin" ]; then
net_handle=$(grep -sE -m 1 "^NetHandle:" $tempdir/whois | awk '{print $NF}' | tr -d ' ')
parent_handle=$(grep -sE -m 1 "^Parent:" $tempdir/whois | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
if [ -n "$net_addr" ]; then
echo -e "\n\nNet:          $net_addr  ($net_name)"
[[ $range_start =~ $REGEX_IP4 ]] && echo -e "\nRange:        $net_range  ($net_mask)\n" || echo -e "\nRange:        $net_range\n"; else
echo -e "\n\nNet:          $net_range  ($net_name)\n"
[[ -n "$print_cidr" ]] && [[ $(echo $print_cidr | wc -w) -lt 7 ]] && echo -e "\nCIDR:         $print_cidr\n"; fi
[[ -n "$orgz" ]] && echo -e "Org:          $orgz\n"
echo -e "\nStatus:       $status, $created"; echo -e "\nNetHandle:    $net_handle | Parent: $parent_handle"; echo "$net_geo"; else
if [ -z "$is_net" ]; then
echo -e "\nNet:          $net_name | $status ($created)"; echo -e "\nRange:        $net_range"; else
echo -e "\nNet:          $net_addr  ($net_name)"
[[ ${net_ip} =~ $REGEX_IP4 ]] && echo -e "\nRange:        $net_range  ($net_mask)"; echo -e "\n\nStatus:       $status ($created)"; fi
echo "$net_geo"; net_org=$(f_ORG_SHORT "$tempdir/whois")
[[ -n "$descr" ]] && echo -e "\nDescr:        $descr"; [[ -n "$net_org" ]] && echo -e "\nOrg:          $net_org"
if [ -n "$parent_net" ]; then
[[ -z "$org_id" ]] && echo ''; [[ -n "$parent" ]] && echo -e "\nParent:       $parent"
if [ -z "$org_id" ]; then
timeout 10 whois -h whois.$rir.net -- "--no-personal $parent_net" > $tempdir/parent_whois
parent_org=$(f_ORG_SHORT "$tempdir/parent_whois"); [[ -n "$parent_org" ]] && echo -e "\nOrg:          $parent_org"; fi; fi; fi
[[ $target_type != "nethandle" ]] && echo '' && f_ROUTE
if [ $rir != "arin" ]; then
if [ $option_detail = "2" ]; then
f_POC "$tempdir/whois"; else
ac=$(grep -E "^admin-c:" $tempdir/whois | cut -d ':' -f 2- | sed 's/^ *//' | head -1)
[[ -n "$ac" ]] && echo '' && f_HEADLINE2 "ADMIN\n" && f_ADMIN_C "$ac"; fi; f_getRIR_OBJECTS "$tempdir/whois"; fi
}
f_NET_SHORT(){
if [ $rir = "lacnic" ] && [ $option_detail != "0" ]; then
f_LACNIC_WHOIS "$tempdir/whois"; else
netrange=$(f_getNET_RANGE "$1"); org=$(f_getORG)
if [ $rir = "arin" ]; then
cidr=$(jq -r '.data.records[]? | .[] | select (.key=="CIDR") | .value' $tempdir/whois.json | tail -1)
netname=$(jq -r '.data.records[]? | .[] | select (.key=="NetName") | .value' $tempdir/whois.json | tail -1)
if [[ $(wc -w <<<"$cidr") -gt 3 ]]; then
[[ $option_detail = "0" ]] && echo -e "\n$netrange | $netname | $org | ARIN\n" || echo -e "Net:          $netrange | $netname | ARIN"; else
[[ $option_detail = "0" ]] && echo -e "\n$cidr | $netname | $org | ARIN\n" || echo -e "Net:          $cidr | $netname | ARIN"; fi
elif [ $rir = "lacnic" ]; then
[[ $option_detail = "0" ]] && echo -e "$netrange | $org | LACNIC\nn"; else
admin_c=$(jq -r '.data.records[]? | .[] | select (.key=="admin-c") | .value' $tempdir/whois.json | head -3 | sort -u)
netname=$(jq -r '.data.records[0]? | .[] | select (.key=="netname") | .value' $tempdir/whois.json)
ctry=$(jq -r '.data.records[0]? | .[] | select (.key=="country") | .value' $tempdir/whois.json)
if [ $option_detail = "0" ]; then
echo -e "\n$netrange | $netname | $ctry | $org | $admin_c | $(f_toUPPER "$rir")\n"; else
echo -e "Net:          $netrange | $netname | $ctry | $(f_toUPPER "$rir")"; fi; fi; fi 
if [ $option_detail = "0" ]; then
origin=$(grep -sE "^Origin-AS:" $tempdir/pwhois | awk '{print $NF}')
[[ -n "$origin" ]] && echo -e "Prefix: $(grep -sE "^Prefix:" $tempdir/pwhois | awk '{print $NF}' | tr -d ' ') (AS $origin)\n"; else
[[ $target_type != "hop" ]] && f_ROUTE
if [ $rir = "arin" ]; then
[[ $target_type != "hop" ]] && f_HEADLINE2 "CONTACT\n" || echo -e "\n\nCONTACT\n"
for o in $org; do
[[ -f $tempdir/org_tmp ]] && rm $tempdir/org_tmp
whois -h whois.arin.net o $o > $tempdir/org_tmp; f_ORG "$tempdir/org_tmp"; done; else
adc1=$(jq -r '.data.records[]? | .[] | select (.key=="admin-c") | .value' $tempdir/whois.json | head -1)
if [ $rir = "apnic" ] && [[ "$adc1" = "JNIC1-AP" ]]; then 
f_JPNIC_WHOIS "$(jq -r '.data.records[]? | .[] | select (.key=="admin-c") | .value' $tempdir/whois.json | tail -1)"; else
[[ $target_type != "hop" ]] && f_HEADLINE2 "ADMIN-C\n" || echo -e "\n\nADMIN-C\n"
if [ -n "$admin_c" ]; then
for ac in $admin_c; do
f_ADMIN_C "$ac"; echo ''; done; fi; fi; fi; fi
}
f_WHOIS_NET(){
local s="$*"
if [ $target_type = "nethandle" ] && [[ $(echo $s | grep -sEc "^NET-") -gt 0 ]]; then
[[ -f $tempdir/arin_net ]] && rm $tempdir/arin_net; [[ -f $tempdir/arin_pocs ]] && rm $tempdir/arin_pocs
whois -h whois.arin.net -- "z + > ! $s" > $tempdir/whois
echo ''; f_Long; echo "NET |  Query:  $s  |  ARIN  |  $file_date"; f_Long
f_NET_INFO  > $tempdir/arin_net
[[ -f $tempdir/arin_net ]] && cat $tempdir/arin_net
f_POC "$tempdir/whois" > $tempdir/arin_pocs; echo '' >> $tempdir/arin_pocs
[[ -f $tempdir/arin_pocs ]] && echo '' && f_HEADLINE2 "CONTACT\n" && cat $tempdir/arin_pocs
cidr1=$(grep -sEa -m 1 "^CIDR:" $tempdir/whois | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | cut -d ' ' -f 1)
[[ -n "$cidr1" ]] && f_ROUTE_CONS "$cidr1"
netgeo=$(jq -r '.data.located_resources[].locations[] | .country' $tempdir/netgeo.json | sort -u | tr '[:space:]' ' ' ; echo '')
[[ $(wc -w <<<$netgeo) -gt 21 ]] && f_HEADLINE2 "NET GEO LOCATION\n" && echo -e "$netgeo\n" | fmt -w 60
f_RESOURCES_NETNAME "$s"; f_SUBNETS "$s"; else
f_getRIR "$s"; f_get_RIPESTAT_WHOIS "$s";
timeout 20 whois -h whois.pwhois.org $1  > $tempdir/pwhois
if [ $option_detail = "0" ]; then
f_NET_HEADER "$s"; else 
if [ $rir = "lacnic" ]; then
whois -h whois.lacnic.net $s > $tempdir/whois; netabuse=$(f_printLACNIC_ABUSE_C)
elif [ $rir = "arin" ]; then
netabuse=$(jq -r '.data.records[]? | .[] | select (.key=="OrgAbuseEmail") | .value' $tempdir/whois.json | grep -v 'hostmaster@arin.net' | sort -u); else
if [ $option_detail = "2" ]; then
whois -h whois.$rir.net -- "-B $s" > $tempdir/whois; else
whois -h whois.$rir.net -- "--no-personal $s" > $tempdir/whois; fi
netabuse=$(grep -E -a -s -m 1 "^% Abuse|^abuse-mailbox:|^e-mail:|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/whois |
grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b")
if [ $rir = "ripe" ] && [[ ${net_ip} =~ $REGEX_IP4 ]]; then
curl -s -m 7 "https://stat.ripe.net/data/address-space-usage/data.json?resource=${s}" > $tempdir/space_usage.json; fi; fi
echo ''; f_Long; echo "NET |  Query:  $s  |  $(f_toUPPER "$rir")  |  $file_date"; f_Long; [[ -n "$netabuse" ]] && echo -e "[@]: $netabuse\n___\n"
if [ $rir = "lacnic" ]; then
[[ -f $tempdir/whois ]] && f_LACNIC_WHOIS "$tempdir/whois"
elif [ $rir = "arin" ]; then
f_ARIN_WHOIS "$s"; else
[[ -f $tempdir/whois ]] && f_NET_INFO "$s"; fi
f_ROUTE_CONS "$s"
if [ $option_detail = "2" ] || [ $option_detail = "3" ]; then
f_NET_DETAILS "$s"; if [ $rir = "arin" ]; then
if [ $option_netdetails2 = "2" ] || [ $option_netdetails2 = "3" ]; then
for n_name in $(cat $tempdir/netnames | sort -u); do
echo ''; f_RESOURCES_NETNAME "$n_name"; done; fi
[[ -f $tempdir/arin_snets ]] && echo '' && cat $tempdir/arin_snets && rm $tempdir/arin_snets; fi; fi; fi; fi
}
#**********************  NETWORK ENUM - CVEs & PING SWEEP ***********************
f_NET_CVEs(){
[[ -f $tempdir/net_ports ]] && rm  $tempdir/net_ports
if [[ $net_ip =~ $REGEX_IP4 ]] ; then
echo ''; f_HEADLINE2 "$1  CPEs/VULNERS  (SOURCE: SHODAN API)\n"
${PATH_ipcalc} -b -n $1 255.255.255.255 | grep -s 'Hostroute:' | cut -d ':' -f 2- | tr -d ' ' |
grep -E -v "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.0$" |
grep -E -v "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.255$" > $tempdir/check.list
for c in $(cat $tempdir/check.list); do
f_CVES "$c"; done; fi
}
f_PING_SWEEP(){
[[ $option_enum = "1" ]] && echo '' && f_HEADLINE2 "$1  PING SWEEP\n"
if [ $option_scope = "1" ] && [ $option_pingsweep = "0" ]; then
[[ $option_root = "y" ]] && sudo ${PATH_nmap} -sn $1  > $tempdir/pingsweep || ${PATH_nmap} -sn $1 > $tempdir/pingsweep
grep -E "Nmap scan report|Host is|rDNS|MAC Address:" $tempdir/pingsweep | sed '/Nmap scan report/i nnn' |
sed 's/Nmap scan report for/*/' | sed '/Host is/i ==' | tr '[:space:]' ' ' | sed 's/nnn/\n\n\n/g' | sed 's/==/\n\n/' |
sed 's/MAC Address:/| MAC Addr:/' | sed 's/Host is/  Host is/' | sed 's/)./)/'; else
if [ $option_pingsweep = "1" ]; then
ps_options=''
elif [ $option_pingsweep = "2" ]; then
echo -e "21\n22\n25\n80\n113\n443" > $tempdir/probes
[[ $option_enum = "1" ]] && [[ -f $tempdir/net_ports ]] && cat $tempdir/net_ports >> $tempdir/probes
port_probes=$(sort -ug $tempdir/probes | sort -R  | sed 's/^/,/' | tr '[:space:]' ' ' | sed 's/^ *//' | sed 's/^\,//' | tr -d ' ')
ps_options="-PE -PP -PS${port_probes} -PA80,443,3389 -PU53,631,40125 -PY80,443,5060"
elif [ $option_pingsweep = "3" ]; then
ps_options=${psweep_array[@]}; fi
if [ $option_root = "y" ] ; then
sudo ${PATH_nmap} $1 -n -sn ${ps_options} -oA ${out} > $tempdir/pingsweep.txt; else
${PATH_nmap} $1 -n -sn ${ps_options} -oA ${out} > $tempdir/pingsweep.txt; fi
grep -E "^Nmap scan report|^Host is|^Nmap done" $tempdir/pingsweep.txt | tr '[:space:]' ' ' | sed 's/Nmap scan report for /\n\n/g' |
sed 's/Host is up/ -  Host is UP /g' | sed 's/Nmap done/\n\nNmap done/' > $tempdir/print_psweep; cat $tempdir/print_psweep
echo ''; f_Long; echo ''; f_EXTRACT_IP4 "$tempdir/print_psweep" > $tempdir/psweep_ips
${PATH_nmap} -iL $tempdir/psweep_ips -sn -Pn -sL --dns-servers=9.9.9.9,1.1.1.1 2>/dev/null |
egrep '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | awk '{print $6,"," $5}' | tr -d '()' | tr -d ' ' |
sed 's/,/,  /'; f_Long; echo -e "\nPROBES SEND:\n\n"
if [ $option_pingsweep = "1" ]; then
[[ $option_root = "y" ]] && echo "-PE -PP -PS443 -PA80" || echo "-PA80,443"; else
echo "$ps_options"; fi; echo -e "\n(PE: ICMP Echo, PP: ICMP Timestamp, PS: TCP SYN, PA: TCP ACK, PU: UDP, PY: SCTP INIT)\n"
f_CLIENT_INFO; fi
}
#**********************  NETWORK ADDRESS SPACE & RELATED RESOURCES ***********************
f_SUBNETS(){
local s="$*"; unset subnets_total; [[ -f $tempdir/subs ]] && rm $tempdir/subs
[[ -f $tempdir/more_specifics ]] && rm $tempdir/more_specifics; [[ -f $tempdir/subdelegations ]] && rm $tempdir/subdelegations
if [ $rir != "lacnic" ]; then
if [ $rir = "arin" ]; then
if [ $target_type != "whois_target" ]; then
if [[ $(grep -c "Subdelegations for" $tempdir/whois) -gt 0 ]]; then
sed '/Subdelegations for/{x;p;x;}' $tempdir/whois | sed -n '/Subdelegations for/,$p' |
grep '(NET' > $tempdir/subdel; fi; fi
[[ -f $tempdir/subdel ]] && subnets_total=$(grep -sc '(NET' $tempdir/subdel)
if [[ $subnets_total -gt 0 ]]; then
echo '' > $tempdir/print_subnets; f_HEADLINE2 "SUBDELEGATIONS: $subnets_total\n" >> $tempdir/print_subnets
sed '/(/{x;p;x;}' $tempdir/subdel | sed 's/(/\n\n(/' | sed 's/^ *//' | sed '/)/G' >> $tempdir/print_subnets; fi; else
f_getMORE_SPECIFICS "$s" > $tempdir/more_specifics
if [ -f $tempdir/mp ]; then
subnets_total=$(grep -sEac "^netname:" $tempdir/m_specifics)
if [[ $subnets_total -gt 0 ]]; then
echo '' | tee $tempdir/print_subnets; f_HEADLINE2 "SUBNETS ($s): $subnets_total\n\n" | tee -a $tempdir/print_subnets; fi; fi; fi
if [[ $subnets_total -gt 0 ]]; then
if [[ $subnets_total -lt 81 ]] ; then
cat $tempdir/more_specifics; echo ''; else
echo -e "\nSubnets: Results have been written to file\n"
cat $tempdir/print_subnets > ${outdir}/SUBNETS.$net_ip.txt; cat $tempdir/more_specifics >> ${outdir}/SUBNETS.$net_ip.txt; fi; fi; fi
}
f_getLESS_SPECIFICS(){
local s="$*"; if [ $rir != "arin" ] && [ $rir != "lacnic" ]; then
timeout 10 whois -h whois.$rir.net -- "--no-personal -L $s" > $tempdir/l_specifics
[[ ${net_ip} =~ $REGEX_IP4 ]] && f_getNETS4 "$tempdir/l_specifics" > $tempdir/lp || f_getNETS6 "$tempdir/l_specifics" > $tempdir/lp
echo -e "LESS SPECIFICS, EXACT\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'
grep -B 1 "IANA-BLK" $tempdir/l_specifics | cut -d ':' -f 2- | sed '/IANA/{x;p;x;}' | sed 's/^ *//'
sed -e '/./{H;$!d;}' -e 'x;/IANA-BLK/d' $tempdir/lp > $tempdir/lp2; f_printNETS "$tempdir/lp2"; echo ''; fi
}
f_getMORE_SPECIFICS(){
local s="$*"; if [ $rir != "arin" ] && [ $rir != "lacnic" ]; then
[[ -f $tempdir/whois_nets ]] && rm $tempdir/whois_nets
timeout 20 whois -h whois.$rir.net -- "--no-personal -M $s" > $tempdir/m_specifics
netcount=$(grep -sEac "^netname:" $tempdir/m_specifics); netcount4=$(grep -sEac "^inetnum:" $tempdir/m_specifics)
if [[ $netcount -gt 0 ]]; then
[[ ${net_ip} =~ $REGEX_IP4 ]] && f_getNETS4 "$tempdir/m_specifics" > $tempdir/mp || f_getNETS6 "$tempdir/m_specifics" > $tempdir/mp
[[ $option_enum = "2" ]] && [[ $option_filter = "n" ]] && echo '' && f_HEADLINE2 "MORE SPECIFICS ($netcount)\n"
if [ $option_filter = "n" ] && [[ $netcount4 -gt 80 ]]; then
grep -E "^inet6num:|^inetnum:|^netname:|^country:|^org:|^admin-c:" $tempdir/mp | sed '/inetnum:/i nnn ' | sed '/inet6num:/i nnn' |
sed '/netname:/i |' | sed '/country:/i |' | sed '/org:/i |' | sed '/admin-c:/i |' | cut -d ':' -f 2- |
sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' | sed 's/nnn/\n\ng' | sed 's/|/\n\n/' | sed 's/^ *//' | sed '/|/G'; echo ''; else
grep -E "^inet6num:|^inetnum:|^netname:|^country:|^org:|^admin-c:" $tempdir/mp |
sed '/inetnum:/i nnn ' | sed '/inet6num:/i nnn' | sed '/inetnum:/a ~=' | sed '/inet6num:/a ~=' | sed '/country/i |' |
sed '/org:/i |' | sed '/admin-c:/i |' | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' |
sed 's/nnn/\n\n/g' | sed 's/^ *//' > $tempdir/whois_nets; echo '' >> $tempdir/whois_nets
if [ $option_filter = "y" ]; then
for f in $(cat $tempdir/filters); do
echo ''; f_HEADLINE2 "MORE SPECIFICS, FILTER: $filter\n"
grep '~=' $tempdir/whois_nets | grep -sEai "${f}.*|*.${f}.*" > $tempdir/filtered
filtered=$(cat $tempdir/filtered)
if [ -n "$filtered" ]; then
echo "$filtered"  | sed '/~=/{x;p;x;}' | sed 's/~=/\n\n/g' | sed 's/^ *//' | sed '/|/G'; f_Long ; echo -e "* CIDR (Input: $s [filtered])\n"
for i in $(cat $tempdir/filtered | awk -F'~=' '{print $1}' | egrep -s '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' |
grep -E "\-" | tr -d ' '); do
${PATH_ipcalc} ${i} | sed '/deaggregate/d'; done; else
echo -e "\nNo results"; fi; done;  echo ''; else
if [[ ${net_ip} =~ $REGEX_IP4 ]]; then
while read line; do
range=$(echo $line | grep -s '~=' | cut -d '~' -f -1 | egrep -s '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | tr -d ' ')
if [ -n "$range" ]; then
print_net=$(echo "$line" | cut -d '=' -f 2- | sed 's/^ *//')
cidr=$(ipcalc -r ${range} | sed '/deaggregate/d' | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ')
echo -e "$cidr | $print_net\n"; fi
done < $tempdir/whois_nets >> $tempdir/subnets; else
cat $tempdir/whois_nets | sed 's/~=/|/g' | sed '/|/G' >> $tempdir/subnets; fi
[[ -f $tempdir/subnets ]] && cat $tempdir/subnets && rm $tempdir/subnets || echo "No results"; fi; fi; fi; fi
}
f_RELATED(){
if [ $target_type = "prefix" ]; then
pfx=$(jq -r '.data.resource' $tempdir/pov.json); else
pfx=$(grep -sE "^Prefix:" $tempdir/pwhois | awk '{print $NF}' | tr -d ' '); fi
curl -s "https://stat.ripe.net/data/related-prefixes/data.json?resource=${pfx}" > $tempdir/rel.json
related=$(jq -r '.data.prefixes[] | {A: .origin_asn, N: .asn_name, P: .prefix, R: .relationship}' $tempdir/rel.json | tr -d '{",}' |
sed 's/^ *//' | sed '/^$/d' | tr '[:space:]' ' ' | sed 's/A: /\n\nAS/g' | sed 's/N:/-/g' | sed 's/R:/|/g' | sed 's/P:/|/g')
if [ -n "$related" ] ; then
[[ $target_type = "prefix" ]] && f_HEADLINE2 "RELATED PREFIXES\n" || f_HEADLINE2 "RELATED PREFIXES  ($pfx)\n" 
less_sp=$(echo "$related" | grep -w 'Overlap - Less Specific'); more_sp=$(echo "$related" | grep -w 'Overlap - More Specific')
adjacent=$(jq -r '.data.prefixes[] | {P: .prefix, AS: .origin_asn, N: .asn_name, R: .relationship}' $tempdir/rel.json  | tr -d '{,"}' |
sed 's/^ *//' | sed '/^$/d' | tr '[:space:]' ' ' | sed 's/P: /\n/g' | sed 's/AS:/| AS/g' | sed 's/N:/-/g' | sed 's/R:/|/g')
adj_left=$(echo "$adjacent" | grep -w 'Adjacency - Left'); adj_right=$(echo "$adjacent" | grep -w 'Adjacency - Right')
rel_asn=$(jq -r '.data.prefixes[].origin_asn' $tempdir/rel.json | sort -ug)
if [ -n "$adj_left" ] ; then
echo -e "\nAdjacent Left\n" ; echo "$adj_left" | sed '/|/G' | cut -d '|' -f -2 | sed 's/| AS:/- AS/g'; fi
if [ -n "$adj_right" ] ; then
echo -e "\nAdjacent Right\n"; echo "$adj_right" | sed '/|/G' | cut -d '|' -f -2 | sed '/|/G' | sed 's/| AS:/- AS/g'; else
[[ -n "$less_sp" ]] || [[ -n "$more_sp" ]] && echo ''; fi
if [ -n "$less_sp" ] ; then
echo -e "Less Specific\n"
for r_as in $rel_asn ; do
lp_sorted=$(echo "$less_sp" | grep -w -E "AS${r_as}")
if [ -n "$lp_sorted" ] ; then
echo ''; echo "$less_sp" | grep -w -E -m 1 "AS${r_as}" | cut -d '|' -f 1 | sed 's/AS/AS /g' ; echo ''
lp_out=$(echo "$less_sp" | grep -w -E "AS${r_as}" | cut -d '|' -f 2 | sed 's/^ *//' | tr '[:space:]' ' ')
echo -e "$lp_out\n" | fmt -s -w 80 ; fi ; done; [[ -n "$more_sp" ]] && echo ''; fi
if [ -n "$more_sp" ] ; then
echo -e "\nMore Specific\n"
for r_as in $rel_asn ; do
mp_sorted=$(echo "$more_sp" | grep -w -E "AS${r_as}")
if [ -n "$mp_sorted" ] ; then
echo ''; echo "$more_sp" | grep -w -E -m 1 "AS${r_as}" | cut -d '|' -f 1 | sed 's/AS/AS /g' ; echo ''
mp_out=$(echo "$more_sp" | grep -w -E "AS${r_as}" | cut -d '|' -f 2 | sed 's/^ *//' | tr '[:space:]' ' ')
echo -e "$mp_out\n" | fmt -s -w 80 ; fi ; done ; fi ; fi
}
f_RESOURCES_NETNAME(){
local n="$*"; unset netcount; unset netcount4; unset netcount6; unset admins_other; unset nets4
if ! [ $rir = "lacnic" ]; then
if [ $rir = "arin" ]; then
if [ $target_type != "whois_target" ]; then
timeout 20 whois -h whois.arin.net -- "n - . $n" | sed '/#/d' | grep '(NET' |
grep -v 'American Registry for Internet Numbers' > $tempdir/nets; fi
egrep '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/nets > $tempdir/nets4_raw
egrep -v '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/nets | grep ':' > $tempdir/nets6_raw
netcount=$(grep -c '(NET' $tempdir/nets); if [[ $netcount -gt 0 ]]; then
if [ -f $tempdir/nets4_raw ]; then
netcount4=$(grep -c '(NET' $tempdir/nets4_raw); sed 's/)/)\n/g' $tempdir/nets4_raw | sed '/)/{x;p;x;}' > $tempdir/nets4
nets4=$(cut -s -d ')' -f 2- $tempdir/nets4_raw | tr -d ' ' | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n); else
netcount4="0"; fi; if [ -f $tempdir/nets6_raw ]; then
netcount6=$(grep -c '(NET' $tempdir/nets6_raw); sed 's/)/)\n/g' $tempdir/nets6_raw | sed '/)/{x;p;x;}' > $tempdir/nets6; else
netcount6="0"; fi; fi; else
[[ $target_type = "whois_target" ]] || timeout 10 whois -h whois.$rir.net -- "--no-personal $n" > $tempdir/nets
netcount=$(grep -sEc "^inetnum:|inet6num:" $tempdir/nets)
netcount4=$(grep -sEc "^inetnum:" $tempdir/nets); netcount6=$(grep -sEc "^inet6num:" $tempdir/nets)
if [[ $netcount -gt 0 ]]; then
if [ -f $tempdir/whois ]; then
grep -Eas "^admin-c:|^nic-hdl:" $tempdir/whois | awk '{print $NF}' | tr -d ' ' > $tempdir/nic_hdls
cat $tempdir/nic_hdls | tr -d ' ' | sed '/^$/d' | sort -u > $tempdir/nh_list1; fi 
if [[ $netcount4 -gt 0 ]]; then
sed -e '/./{H;$!d;}' -e 'x;/inetnum:/!d' $tempdir/nets | grep -E "^inetnum:|^country:|^admin-c:" | sed 's/admin-c:/|admin-c;/' |
sed 's/country://' | tr -d ' ' | tr '[:space:]' ' ' | sed 's/inetnum:/\n|/g' | awk '{print $2,$1,$3}'|
sed 's/|/| /g' > $tempdir/nets4
cat $tempdir/nets4 | awk -F'admin-c;' '{print $2}' | sed 's/^ *//' | sed '/^$/d' | tr -d ' ' > $tempdir/nh_list2
nets4=$(grep -E "^inetnum:" $tempdir/nets | cut -d ':' -f 2- | sed 's/^ *//' | egrep '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' |
tr -d ' '); fi
if [[ $netcount6 -gt 0 ]]; then
sed -e '/./{H;$!d;}' -e 'x;/inet6num:/!d' $tempdir/nets | grep -E "^inet6num:|^country:|^admin-c:" | sed 's/admin-c:/|admin-c;/' |
sed 's/country://' | tr -d ' ' | tr '[:space:]' ' ' | sed 's/inet6num:/\n|/g' | awk '{print $2,$1,$3}'| sed 's/|/| /g' > $tempdir/nets6
cat $tempdir/nets6 | awk -F'admin-c;' '{print $2}' | sed 's/^ *//' | sed '/^$/d' | tr -d ' ' >> $tempdir/nh_list2; fi
if [ $target_type != "whois_target" ] && [ -f $tempdir/nh_list1 ]; then
sort -u $tempdir/nh_list2 > $tempdir/nh_list2_sorted
admins_other=$(comm -1 -3 $tempdir/nh_list1 $tempdir/nh_list2_sorted | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' | head -5); fi; fi; fi
[[ $netcount4 -gt 20 ]] && action_ipv4="(see file) " || action_ipv4=''
[[ $netcount6 -gt 15 ]] && action_ipv6="(see file) " || action_ipv6=''
[[ $domain_enum = "true" ]] && echo -e "\n'$n' - Networks (global)  -  IPv6: $netcount6 $action_ipv6 IPv4: $netcount $action_ipv4\n"
if [ $netcount -gt "1" ] || [ $domain_enum = "true" ]; then
if [ $domain_enum = "false" ] && [ $target_type != "other" ]; then
echo ''; f_HEADLINE2 "NETWORK RESOURCES FOR '$n'\n"; echo -e "IPv6: $netcount6 $action_ipv6 IPv4: $netcount4 $action_ipv4\n"; fi
if [[ $netcount6 -gt 0 ]]; then
if [[ $netcount6 -lt 16 ]]; then
cat $tempdir/nets6; else
echo '' >> $outdir/NetRanges.$n.txt; f_Long >> $outdir/NetRanges.$n.txt
echo -e "IPv6 RESOURCES FOR '$n' ($rir)\n" >> $outdir/NetRanges.$n.txt
cat $tempdir/nets6 >> $outdir/NetRanges.$n.txt; fi; fi
if [[ $netcount4 -gt 0 ]]; then
if [[ $netcount4 -lt 21 ]]; then
cat $tempdir/nets4 > $tempdir/resources_v4; [[ -n "$nets4" ]] && f_DEAGGREGATE "$nets4" >> $tempdir/resources_v4
cat $tempdir/resources_v4; else
echo '' >> $outdir/NetRanges.$n.txt; f_Medium >> $outdir/NetRanges.$n.txt
echo -e "\nIPv4 RESOURCES FOR '$n' ($rir)\n" >> $outdir/NetRanges.$n.txt
cat $tempdir/nets4 >> $outdir/NetRanges.$n.txt; fi; fi
if ! [ $rir = "arin" ] && [ -n "$admins_other" ]; then
f_Short; echo -e "\nOTHER CONTACTS FOR '$n'"
for i in $admins_other; do
whois -h whois.$rir.net -- "-r -F $i" | tr -d '*' | sed 's/^ *//' > $tempdir/acwhois
grep -E "^pn:|^ro:|^ad:|^ph:|^nh:" $tempdir/acwhois | sed '/pn:/i nnn' | sed '/ro:/i nnn' | sed '/pn:/a nnn' | sed '/ro:/a nnn' |
sed '/ph:/i |' | sed '/nh:/i | ' | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' | sed 's/nnn/\n\n/g' |
sed 's/|/\n\n/' | sed 's/^ *//'; done > $tempdir/admins_other; [[ -f $tempdir/admins_other ]] && cat $tempdir/admins_other; fi; fi; fi
[[ -f $tempdir/nets ]] && rm $tempdir/nets; [[ -f $tempdir/nets4 ]] && rm $tempdir/nets4; [[ -f $tempdir/nets6 ]] && rm $tempdir/nets6
}
#**********************  NETWORK IP GEOLOCATION & ALLOCATION COUNTRY ***********************
f_NETGEO(){
local g="$*"
if [[ ${g} =~ "-" ]]; then
geo_target=$(echo $g | cut -d '-' -f 1 | tr -d ' '); else
geo_target="$g"; fi
curl -s -m 7 --location --request GET "https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource=${geo_target}" > $tempdir/netgeo.json
geo_max=$(jq -r '.data.located_resources[] | .locations[].country' $tempdir/netgeo.json | sort -u | tr '[:space:]' ' ' |
sed 's/^[ \t]*//;s/[ \t]*$//')
geo_rir=$(curl -s -m 7 --location --request GET "https://stat.ripe.net/data/rir-geo/data.json?resource=${geo_target}" |
jq -r '.data.located_resources[].location' | tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//')
if [ $rir = "arin" ] || [ $rir = "lacnic" ]; then
geo_whois=''; else
geo_whois=$(grep -E "^country:" $tempdir/whois | awk '{print $NF}' | head -1); fi
if [ -n "$geo_whois" ]; then
if [[ $(echo "$geo_max" | wc -w ) -lt 22 ]]; then
echo -e "\nGeo:          $geo_rir (RIR), $geo_whois (whois), $geo_max (maxmind)"; else
echo -e "\nGeo:          $geo_rir (RIR), $geo_whois (whois)"; fi; else
if [[ $(echo "$geo_max" | wc -w ) -lt 22 ]]; then
echo -e "\nGeo:          $geo_rir (RIR), $geo_max (maxmind)"; else
echo -e "\nGeo:          $geo_rir (RIR)"; fi; fi
}
f_NETGEO_MAXMIND(){
local s="$*"
[[ -f $tempdir/netgeo.json ]] || curl -s https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource=${s} > $tempdir/netgeo.json
jq -r '.data.located_resources[].locations | .[] | .resources[]' $tempdir/netgeo.json | sort -u -V > $tempdir/nets_geo.list
netcount=$(cat $tempdir/nets_geo.list | wc -w); locations=$(jq -r '.data.located_resources[].locations | .[]' $tempdir/netgeo.json)
f_HEADLINE2 "GEOGRAPHIC DISTRIBUTION\n" | tee $tempdir/geo_header
echo "$locations" | jq -r '{N: .resources[], Lat: .latitude, Lon: .longitude, cov: .covered_percentage, Country: .country, C: .city}' |
tr -d '{,"}' | sed 's/^ *//' | sed '/^$/d' | tr '[:space:]' ' ' | sed 's/N: /\n\n/g' | sed 's/ Lon: /\,/g' | sed 's/Lat:/ -  Lat\/Lon:/g' |
sed 's/cov:/(covered:/g' | sed 's/Country:/%) | Country:/g' | sed 's/C://g' >> $tempdir/geo_temp; echo '' >> $tempdir/geo_temp
if [[ $netcount -gt "3" ]] ; then
echo -e "\n_______________________________________\n" >> $tempdir/geo_temp
cat $tempdir/nets_geo.list | tr '[:space:]' ' ' | fmt -s -w 40 | sed 's/ /  /g' | sed 's/^ *//' >> $tempdir/geo_temp
echo '' >> $tempdir/geo_temp ; fi
if [[ $netcount -gt 51 ]] ; then
echo -e "\nOutput has been written to file ($netcount networks)" ; f_Long > $outdir/NET_GEOLOC.$net_ip.txt
echo '' > $outdir/NET_GEOLOC.$net_ip.txt; cat $tempdir/geo_header >> $outdir/NET_GEOLOC.$net_ip.txt
cat $tempdir/geo_temp >> $outdir/NET_GEOLOC.$net_ip.txt ; else
cat $tempdir/geo_temp; fi ; rm $tempdir/netgeo.json; rm $tempdir/geo_temp; echo ''
}
#**********************  NETWORK RDNS / REVERSE IP / REVERSE DNS DELEGATIONS  ***********************
f_DELEGATION(){
if [ $rir = "ripe" ]; then
unset nserver; curl -s "https://stat.ripe.net/data/reverse-dns/data.json?resource=$1" |
jq -r '.data.delegations[] | .[] | .key, .value' > $tempdir/delegation
nserver=$(grep -sEoc "nserver" $tempdir/delegation)
if [[ $nserver -gt 0 ]]; then
grep -sEa -A 1 "^domain|^nserver|^zone-c|^descr" $tempdir/delegation | sed '/^--/d' | sed 's/zone-c/| zone-c:/' | tr '[:space:]' ' ' |
sed 's/domain/\ndomain/g' | sort -u | sed 's/domain /\n\n/' | sed 's/nserver /\n\n/' | sed 's/descr/\n\n/' | sed 's/nserver//g' |
sed 's/descr//g' | sed 's/\&amp;/\&/g'| sed 's/^ *//' > $tempdir/zone; zonec=$(sed -n '/^zone-c/{n;p;}' $tempdir/delegation)
cat $tempdir/zone; fi; fi
}
f_NET_RDNS(){
f_HEADLINE2 "$1  RDNS"; f_RESOLVE_HOSTS4 "$1"
if [ $rdnsv6 = "true" ] && [ -f $tempdir/resolved4 ]; then
awk '{print $NF}' $tempdir/resolved4 | tr -d ' ' > $tempdir/rdns_records
resolve6=$(f_RESOLVE_HOSTS6 "$tempdir/rdns_records")
[[ -n "$resolve6" ]] && f_HEADLINE2 "IPV6 HOSTS\n" && echo -e "$resolve6\n"; fi
}
f_REV_IP(){
curl -s -m 30 "https://api.hackertarget.com/reverseiplookup/?q=$1${api_key_ht}" | sed 's/No DNS A records found/\nno_records\n/' > $tempdir/revip
f_HEADLINE2 "$1  REVERSE IP  (SOURCE: HACKERTARGET.COM)\n"
if [[ $(wc -l < $tempdir/revip) -lt 2 ]]; then
echo -e "No results\n"; else
echo '' | tee -a $tempdir/revip
if [[ $(egrep -o -c '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/revip) -gt 1 ]]; then
awk -F ',' '{print $2",\t\t"$1}' $tempdir/revip | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n ; else
if [[ $(wc -l < $tempdir/revip) -lt "1001" ]] ; then
dig +noall +answer +noclass +nottlid -f $tempdir/revip | sed 's/A/,/' | sed '/NS/d' | sed '/CNAME/d' | tr -d ' ' | sed 's/,/  /g' ; else
cat $tempdir/revip ; echo '' ; fi ; fi; fi
}
#**********************  NETWORK ENUM - OTHER ***********************
f_DUMP_ROUTER_DHCP_6(){
iflist6=$(ip -6 -br addr show up scope global | grep 'UP' | cut -d ' ' -f 1 | tr -d ' ' | sort -uV)
if [ -n "$PATH_dump_router6" ] || [ -n "$PATH_dump_dhcp6" ]; then
if [ -n "$iflist6" ]; then
for i6 in $iflist6; do
f_HEADLINE2 "Router, DHCPv6 solicitation ($i6)\n"
[[ -n "$PATH_dump_router6" ]] && sudo ${PATH_dump_router6} $i6 | sed '/Router:/{x;p;x;G}' && echo ''
[[ -n "$PATH_dump_dhcp6" ]] && sudo ${PATH_dump_dhcp6} -N $i6 && echo ''; done; fi; else
[[ -n "$PATH_dump_router6" ]] || echo -e "No executable found for atk6-dump_router6\n"
[[ -n "$PATH_dump_dhcp6" ]] || echo -e "No executable found for atk6-dump_dhcp6\n"; fi
}
f_ipCALC(){
local s="$*"; ${PATH_ipcalc} -b -n ${s} > $tempdir/ipcal
hosts=$(grep 'Hosts/Net' $tempdir/ipcal | awk '{print $2}'); mask=$(grep 'Netmask' $tempdir/ipcal | awk '{print $2}')
echo "$mask, $hosts hosts"; rm $tempdir/ipcal
}
f_printNETS(){
local nf="$*"; grep -E "^inetnum:|^inet6num:|^netname:|^country:|^org:|^admin-c:" ${nf} | sed '/inetnum:/i nnn ' |
sed '/inet6num:/i nnn' | sed '/netname:/i |' | sed '/country:/i |' | sed '/org:/i |' | sed '/admin-c:/i |' | cut -d ':' -f 2- |
sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' | sed 's/nnn/\n\n/g' | sed 's/|/\n\n/' | sed 's/^ *//'; echo ''
}

#-------------------------------  DNS (GENERAL)  -------------------------------

f_dnsCHAIN(){
unset queried_ns; unset auth_nservers; revert_to_local="false"
curl -s -m 15 --location --request GET "https://stat.ripe.net/data/dns-chain/data.json?resource=$1" > $tempdir/chain.json
auth_nservers=$(jq -r '.data.authoritative_nameservers[]?' $tempdir/chain.json)
queried_ns=$(jq -r '.data.nameservers[0]?' $tempdir/chain.json)
forward_nodes=$(jq -r '.data.forward_nodes' $tempdir/chain.json | tr -d '{,"}' | sed 's/^ *//' | sed '/^$/d' | tr -d '][' | sed '2i\\')
node_count=$(f_countW "$forward_nodes")
if [[ $1 =~ $REGEX_IP46 ]]; then
[[ $queried_ns = "null" ]] && revert_to_local="true"; else
[[ $(f_countW "$forward_nodes") -lt 2 ]] && revert_to_local="true"; fi
if [ $revert_to_local = "true" ]; then
f_LOCAL_DNS "$1"; else
if [ -n "$auth_nservers" ]; then
print_authns=$(echo "$auth_nservers" | sort -uV | tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/ /  /g' | fmt -s -w 80)
if [ $target_type = "hop" ] || [ $target_type = "web" ] || [ $target_type = "mailserv" ]; then
echo -e "\n$forward_nodes\n"; else
echo -e "$forward_nodes\n\nAUTH NS  (rDNS)\n\n$print_authns\n"; fi
if [ $target_type = "default" ] || [ $target_type = "hostname" ] || [ $target_type = "whois_target" ] || [ $target_type = "other" ]; then
f_EXTRACT_IP4 "$(jq -r '.data.forward_nodes[] | .[]' $tempdir/chain.json)" | tee -a $tempdir/x4 >> $tempdir/host_ipv4
f_EXTRACT_IP6 "$(jq -r '.data.forward_nodes[] | .[]' $tempdir/chain.json)" | tee -a $tempdir/x6 >> $tempdir/host_ipv6
if [ -f $tempdir/host_ipv4 ]; then
f_whoisTABLE "$tempdir/host_ipv4"; cut -d '|' -f -5 $tempdir/whois_table.txt | sed '/^$/d' | sed '/NET NAME/{x;p;x;G}'
echo ''; fi; fi; fi; fi
}
f_getHostRevDNS(){
unset rdns; unset ip_alt; unset print_rdns; unset print_ip_alt
rdns=$(dig @1.1.1.1 +short -x $1 | rev | cut -d ' ' -f 1 | cut -c 2- | rev)
if [ -n "$rdns" ]; then
print_rdns=$(echo "$rdns" | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ')
if [[ $(wc -w <<<$rdns) -gt 4 ]]; then
[[ $target_type = "default" ]] && echo -e "\nrDNS:\n\n$print_rdns\n" | fmt -w 70 && f_Long; else
if [[ $1 =~ $REGEX_IP4 ]]; then
ip_alt=$(for r in $rdns; do
dig @1.1.1.1 aaaa +short $r | grep ':'; done); else
ip_alt=$(for r in $rdns; do
dig @1.1.1.1 a +short $r | grep -sEo "$REGEX_IP4" ; done); fi
if [ -n "$ip_alt" ]; then
print_ip_alt=$(echo "$ip_alt" | sed 's/^ *//' | tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//')
[[ $domain_enum = "true" ]] && echo -e "rDNS: $print_rdns ($print_ip_alt)\n" || echo -e "\nrDNS:         $print_rdns ($print_ip_alt)"; else
[[ $domain_enum = "true" ]] && echo -e "rDNS: $print_rdns" || echo -e "\nrDNS:         $print_rdns"; fi; fi; else
if [ $target_type != "hop" ]; then
[[ $domain_enum = "true" ]] && echo -e "rDNS: No PTR record\n" || echo -e "\nrDNS:         No PTR record"; fi; fi
}
f_LOCAL_DNS(){
if [[ $1 =~ ":" ]]; then
${PATH_nmap} -6 --system-dns -R --resolve-all -Pn -sn -sL $1 2>/dev/null > $tempdir/local_dns; else
${PATH_nmap} --system-dns -R --resolve-all -Pn -sn -sL $1 2>/dev/null > $tempdir/local_dns; fi
if [ -f $tempdir/local_dns ]; then
grep -E "Nmap scan report|Other addresses" $tempdir/local_dns |  sed 's/Nmap scan report for //' |
sed 's/Other addresses for //' | sed 's/(not scanned):/ - /' | sed 's/(/ -  /' | tr -d ')'; rm $tempdir/local_dns; fi
}
f_RESOLVE_v4(){
dig @9.9.9.9 a +short $1 | grep -sEo "$REGEX_IP4" | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n -u
}
f_RESOLVE_v6(){
dig @9.9.9.9 aaaa +short $1 | grep -sEo "$REGEX_IP6" | sort -uV
}
f_RESOLVE_HOSTS4(){
unset hfile_resolved; [[ -f $tempdir/resolved4 ]] && rm $tempdir/resolved4
if [ $target_type = "net" ]; then
${PATH_nmap} $1 -sn -Pn -sL ${nmap_ns} 2>/dev/null > $tempdir/hfile_resolved; else
local hfile="$*"; ${PATH_nmap} ${resolve_all} -sn -Pn -sL -iL $hfile ${nmap_ns} 2>/dev/null > $tempdir/hfile_resolved; fi
if [ -f $tempdir/hfile_resolved ]; then
hfile_resolved_raw=$(grep 'scan report' $tempdir/hfile_resolved | grep ')' | egrep '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | rev |
cut -d ' ' -f -2 | rev | sed 's/(/,/' | tr -d ')' | sort -t ',' -k 1 | tr -d ' ')
if [ -n "$hfile_resolved_raw" ] && [[ $(echo "$hfile_resolved_raw" | grep -c ',' ) -gt 0 ]] ; then
if [ $domain_enum = "true" ]; then
echo "$hfile_resolved_raw"; if [[ $(grep -c 'Other addresses for' $tempdir/hfile_resolved) -gt 0 ]]; then
grep -E "^Other addresses for" $tempdir/hfile_resolved | awk '{print $4","$7}' |  sed 's/,/\n  ->  /' |
sed '/./{x;p;x;}' > $tempdir/subs6; fi; else
hfile_resolved=$(echo "$hfile_resolved_raw" | sort -t ',' -k 1 | sed 's/,/ => /' | awk '{print $3 "\t\t" $2 "\t" $1}')
if [ $target_type = "net" ]; then
echo -e "\n$hfile_resolved\n" | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n | tee $tempdir/resolved4; else
echo -e "\n$hfile_resolved\n" | tee $tempdir/resolved4; fi; fi; else
[[ $domain_enum = "false" ]] && echo -e "No results\n"; fi; else 
[[ $domain_enum = "false" ]] && echo -e "Error getting results\n"; fi
}
f_RESOLVE_HOSTS6(){
local hfile="$*"; unset hfile_resolved6; ${PATH_nmap} -6 -sn -Pn -sL -iL $hfile ${nmap_ns} 2>/dev/null > $tempdir/hfile_resolved
if [ -f $tempdir/hfile_resolved ]; then
hfile_res6=$(grep 'scan report' $tempdir/hfile_resolved | grep ')' | tr -d '()' | awk '{print $6","$5}' |
sort -t ',' -k 1 | sed 's/,/\n  ->  /' | sed '/./{x;p;x;}')
[[ -n "$hfile_res6" ]] && echo -e "\n$hfile_res6\n" || echo -e "No results\n"; rm $tempdir/hfile_resolved; fi
}
f_VHOSTS(){
unset vhosts_count; if [[ $1 =~ $REGEX_IP4 ]]; then
f_HEADLINE2 "REVERSE IP (VHOSTS)" | tee -a $tempdir/vhosts_out
f_BOGON "$1"; if [ $bogon = "TRUE" ] ; then
echo -e "BOGON Address detected [$1]\n" | tee -a $tempdir/vhosts_out; else
curl -s https://api.hackertarget.com/reverseiplookup/?q=${1}${api_key_ht} > $tempdir/vhosts_raw
echo '' >> $tempdir/vhosts_raw
if [ -f $tempdir/vhosts_raw ]; then
grep '\.' $tempdir/vhosts_raw | sed 's/^[ \t]*//;s/[ \t]*$//' | sort -fiu > $tempdir/vhosts
vhosts_count=$(wc -w < $tempdir/vhosts); echo -e "\n$1: VHosts: $vhosts_count\n\n" | tee -a $tempdir/vhosts_out
cat $tempdir/vhosts | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -s -w 80 | sed G > $tempdir/vhosts.list
if [ $report = "true " ] &&  [[ $vhosts_count -gt 51 ]]; then
echo -e "List of hosts has been written to file\n"; cat $tempdir/vhosts.list >> $tempdir/vhosts_out; else
cat $tempdir/vhosts.list | tee -a $tempdir/vhosts_out; fi; else
echo -e "$1: VHosts: No resulsts\n" | tee -a $tempdir/vhosts_out; fi; fi; fi
}

#-------------------------------  DNS RESOURCE RECORDS  -------------------------------

f_AXFR(){
local s="$*"; if [ $domain_enum = "true" ] || [ $option_dns != "1" ]; then 
echo ''; f_HEADLINE "ZONE TRANSFER |  $s  | $file_date"; else
f_HEADLINE2 "ZONE TRANSFER\n"; fi
curl -s https://api.hackertarget.com/zonetransfer/?q=${s}${api_key_ht} > $tempdir/zone.txt
egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/zone.txt | sort -u -V >> $tempdir/ips.list
echo '' >> $tempdir/zone.txt; cat $tempdir/zone.txt
}
f_DNS_REC(){
local s="$*"
[[ -f $tempdir/dhostv4 ]] && rm $tempdir/dhostv4; [[ -f $tempdir/dhostv6 ]] && rm $tempdir/dhostv6
if [ $domain_enum = "true" ]; then
echo -e "\n"; f_HEADLINE "$s  DNS RECORDS"; else 
echo -e "\n"; f_Long; echo "[DNS RECORDS]  $s  $file_date"; f_Long; echo ''; f_WHOIS_STATUS "$s"; echo ''; f_Long; fi
echo -e "\nDOMAIN HOST\t\t$s\n\n"
dig ${dig_array[@]} ${ttl} $s | grep -w 'A' | tee $tempdir/hostsA.list | awk '{print $2"\t\t\t"$4}'
dig aaaa ${dig_array[@]} ${ttl} $s | grep -w 'AAAA' | tee $tempdir/hostsAAAA.list | awk '{print $2"\t\t\t"$4}'
f_EXTRACT_IP4 "$tempdir/hostsA.list" | tee $tempdir/rec_ips.list > $tempdir/dhostv4
[[ -f $tempdir/hostsAAAA.list ]] && awk '{print $NF}' $tempdir/hostsAAAA.list | sort -uV | tee $tempdir/dhostv6 > $tempdir/rec_ips6.list
f_MX "${s}"; f_NS "$s"; f_SOA "$s"; [[ $rfc1912 = "true" ]] && f_RFC1912 "$s"
[[ $option_dns_details = "0" ]] || [[ $option_dns_details = "1" ]] && f_MX_CHECK
txt_rec=$(dig ${nssrv_dig} +short txt ${s})
f_EXTRACT_IP4 "$txt_rec" > $tempdir/txt+srv; f_EXTRACT_IP4_ALL "$txt_rec" | cut -d '/' -f 1 >> $tempdir/rec_ips.list
f_SRV_REC "$s"; if [ -n "$txt_rec" ] ; then
echo ''; f_Long; echo -e "\nTXT RECORDS\n"; echo "$txt_rec" | sed '/\"/{x;p;x;}' | fmt -s -w 80; fi
sort -t . -k 1,1n -k 2,2n -u $tempdir/rec_ips.list | tee $tempdir/zone_lookups4 > $tempdir/pfx_lookups
[[ -f $tempdir/rec_ips6.list ]] && sort -t ':' -k 2,2 -u $tempdir/rec_ips6.list | tee $tempdir/zone_lookups6 >> $tempdir/pfx_lookups
f_whoisTABLE "$tempdir/rec_ips.list"; echo '' > $tempdir/pwhois_table; f_Long >> $tempdir/pwhois_table
cat $tempdir/whois_table.txt | cut -d '|' -f -5 | sed '/^$/d' | sed '/NET NAME/G' >> $tempdir/pwhois_table
cat $tempdir/pwhois_table; f_Long; echo -e "\nPREFIXES\n\n"
for p in $(cat $tempdir/pfx_lookups); do
f_ROUTE "${p}"; echo ''; done
if [ $option_connect = "0" ] || [ $domain_enum = "false" ]; then
dns_caa=$(dig @1.1.1.1 +short caa $s); [[ -n "$dns_caa" ]] && f_Long && echo -e "\nDNS CAA\n\n$dns_caa\n"; fi
if [ $domain_enum = "false" ]; then
[[ "$dns_opt2" = "1" ]] || [[ "$dns_opt2" = "3" ]] && f_AXFR "$s"
if [ $option_connect != "0" ] ; then
[[ "$dns_opt2" = "2" ]] || [[ "$dns_opt2" = "3" ]] && f_PING_DNSRR; echo ''; f_Long
echo -e "\nChecking name server response via SOA record query ...\n"
dig @1.1.1.1 +short +nssearch $x > $tempdir/nssearch
serials=$(grep 'SOA' $tempdir/nssearch | awk '{print $4}' | tr -d ' ' | sort -u)
if [[ $(f_countL "$serials") = 1 ]]; then
echo -e "Zone serials match (ok): $serials\n"
grep 'SOA' $tempdir/nssearch | awk '{print $11,$12,$13,$14}' | sed 's/in//' | sed 's/ ms./ms/' | awk '{print $2,"for",$1}'; else
echo -e "Zone serials not matching (not ok)\n\n"; grep 'SOA' $tempdir/nssearch | awk '{print $2,$4,$9,$11,$12,$13,$14}' |
sed 's/in/ ->/' | sed 's/ ms./ms/'; fi; fi; fi; [[ $option_connect != "0" ]] && f_NS_DETAILS
if [ $domain_enum = "true" ]; then
cat $tempdir/rec_ips.list >> $tempdir/ips.list; else
f_FCRDNS; f_AUTHNS_PTR; f_TTL_ALT; fi
}
f_DNS_SHORT(){
local s="$*"; ns_soa=$(dig @1.1.1.1 soa +noall +answer +noclass +nottlid $s | grep 'SOA' | awk '{print $3,$4}')
if [ $domain_enum = "true" ]; then 
f_HEADLINE2 "$s  DNS RECORDS\n"; else 
echo ''; f_Long; echo "[DNS]  $s  ($file_date)"; f_Long; echo ''; fi 
if [ -z "$ns_soa" ]; then
f_LOCAL_DNS "$s"; else
unset hostsA; unset hostsAAAA; txt_rec=$(dig @1.1.1.1 +short txt ${s} | fmt -s -w 80)
echo -e "\nDOMAIN HOST\t\t${s}\n"; hostsA=$(dig ${dig_array[@]} ${ttl} $s | grep -w 'A' | awk '{print $2"\t\t\t"$4}')
hostsAAAA=$(dig aaaa ${dig_array[@]} ${ttl} $s | grep -w 'AAAA' | awk '{print $2"\t\t\t"$4}')
[[ -z "$hostsA" ]] && [[ -z "$hostsAAAA" ]] && echo -e "No A/AAAA record found\n"
if [ -n "$hostsA" ]; then
echo -e "\n$hostsA"; echo "$hostsA" | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' >> $tempdir/domain_ips; fi
[[ -n "$hostsAAAA" ]] && echo -e "\n$hostsAAAA"; f_MX "$s" > $tempdir/dnsrec;
f_NS "$s" >> $tempdir/dnsrec; cat $tempdir/dnsrec; echo -e "\n\nSOA\n"; dig @1.1.1.1 soa +short $s
if [ -n "$txt_rec" ]; then
echo ''; f_Long; echo -e "\nTXT\n\n$txt_rec"; f_EXTRACT_IP4_ALL "$txt_rec" | cut -d '/' -f 1 > $tempdir/domain_ips; fi
f_EXTRACT_IP4 "$tempdir/dnsrec" >> $tempdir/domain_ips
[[ $domain_enum = "true" ]] && [[ $option_connect != "0" ]] && f_SRV_REC "$s"
if [ $domain_enum = "false" ]; then
f_whoisTABLE "$tempdir/domain_ips"; echo ''; f_Long
cat $tempdir/whois_table.txt | cut -d '|' -f 1,2,4,5,6 | sed '/^$/d' | sed '/NET NAME/G'; fi; fi
}
f_FCRDNS(){
f_HEADLINE2 "FORWARD CONFIRMED REVERSE DNS\n"
if [ -f $tempdir/dhostv4 ] || [ -f $tempdir/dhostv6 ]; then
echo -e "\nDOMAIN HOST:  $x\n";
[[ -f $tempdir/dhostv4 ]] && f_getFCRDNSv4 "$x"; [[ -f $tempdir/dhostv6 ]] && f_getFCRDNSv6 "$x"; fi 
if [ -f $tempdir/mx_hosts ]; then
[[ -f $tempdir/dhostv4 ]] || [[ -f $tempdir/dhostv6 ]] && echo ''; echo -e "\nMX RECORDS\n"
for m in $(sort -uV $tempdir/mx_hosts); do
echo -e "\n$m:\n"; f_getFCRDNSv4 "$m"
[[ -f $tempdir/mx_ipv6.list ]] && f_getFCRDNSv6 "$m"; done; echo ''; fi; echo -e "\nNS RECORDS\n"
for n in $(sort -uV $tempdir/ns_servers); do
echo -e "\n$n:\n"; f_getFCRDNSv4 "$n"; [[ -f $tempdir/ns_ipv6.list ]] && f_getFCRDNSv6 "$n"; done; echo ''
}
f_getFCRDNSv4(){
local s="$*"; [[ -f $tempdir/fcrdnsv4 ]] && rm $tempdir/fcrdnsv4
${PATH_nmap} -Pn -sn -R --script=fcrdns ${nmap_ns} ${s} 2>/dev/null > $tempdir/fcrdnsv4
if [[ $(grep -c 'Host script results:' $tempdir/fcrdnsv4) -gt 0 ]]; then
grep '|' $tempdir/fcrdnsv4 | tr -d '|_' | sed 's/status:/-/' | sed 's/addresses:/-/' | sed 's/reason:/-/' |
sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' | sed 's/fcrdns://' | sed 's/^ *//' | sed 's/: - pass/ - PASS/' |
sed 's/: - [Ff][Aa][Ii][Ll]/ - FAIL/' | sed 's/(No PTR record)/No PTR (IPv4)/' | sed 's/^/   /'; echo ''; fi
}
f_getFCRDNSv6(){
local s="$*"; [[ -f $tempdir/fcrdnsv6 ]] && rm $tempdir/fcrdnsv6
${PATH_nmap} -6 -Pn -sn -R --script=fcrdns ${nmap_ns} ${s} 2>/dev/null > $tempdir/fcrdnsv6
if [[ $(grep -c 'Host script results:' $tempdir/fcrdnsv6) -gt 0 ]]; then
grep '|' $tempdir/fcrdnsv6 | tr -d '|_' | sed 's/status:/-/' | sed 's/addresses:/-/' | sed 's/reason:/-/' |
sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' | sed 's/fcrdns://' | sed 's/^ *//' | sed 's/: - pass/ - PASS/' |
sed 's/: - [Ff][Aa][Ii][Ll]/ - FAIL/' | sed 's/(No PTR record)/No PTR (IPv6)/' | sed 's/^/   /'; echo ''; fi
}
f_PING_DNSRR(){
f_HEADLINE2 "NPING\n"
if [ -f $tempdir/dhostv4 ] || [ -f $tempdir/dhostv6 ]; then
echo -e "\nDOMAIN HOST:  $x\n"; if [ -f $tempdir/dhostv4 ]; then
for a in $(cat $tempdir/dhostv4); do
${PATH_nping} --safe-payloads --tcp-connect -p 80 -c 4 $a > $tempdir/np; f_printNPING; done; fi
if [ -f $tempdir/dhostv6 ]; then
for z in $(cat $tempdir/dhostv6); do
${PATH_nping} -6 --safe-payloads --tcp-connect -p 80 -c 4 $z > $tempdir/np; f_printNPING; done; fi; echo ''; fi
if [ -f $tempdir/mx_hosts ]; then
echo -e "\n\nMX RECORDS"; for m in $(sort -uV $tempdir/mx_hosts); do
echo -e "\n\n$m:"; for mxa in $(f_RESOLVE_v4 "$m"); do
${PATH_nping} --safe-payloads --tcp-connect -p 25 -c 4 $mxa > $tempdir/np; f_printNPING; done
for mxz in $(f_RESOLVE_v6 "$m"); do
${PATH_nping} -6 --safe-payloads --tcp-connect -p 25 -c 4 $mxz > $tempdir/np; f_printNPING; done; done; echo ''; fi
echo -e "\n\nNS RECORDS"; for n in $(sort -uV $tempdir/ns_servers); do
echo -e "\n\n$n:"; for nsa in $(f_RESOLVE_v4 "$n"); do
${PATH_nping} --safe-payloads --tcp-connect -p 53 -c 4 $nsa > $tempdir/np; f_printNPING; done
for nsz in $(f_RESOLVE_v6 "$n"); do
${PATH_nping} -6 --safe-payloads --tcp-connect -p 53 -c 4 $nsz > $tempdir/np; f_printNPING; done; done; echo ''
if [ -f $tempdir/services ]; then
echo -e "\n\nSRV RECORDS"
for srv in $(cat $tempdir/services); do
srv_host=$(echo "$srv" | cut -s -d ';' -f 2 | tr -d ' '); dst_port=$(echo "$srv" | cut -s -d ';' -f 1 | tr -d ' ')
echo -e "\n\n$srv_host"
for sa in $(f_RESOLVE_v4 "$srv_host"); do
${PATH_nping} --safe-payloads --tcp-connect -p $dst_port -c 4 $sa > $tempdir/np; f_printNPING; done
for sz in $(f_RESOLVE_v6 "$srv_host"); do
${PATH_nping} -6 --safe-payloads --tcp-connect -p $dst_port -c 4 $sz > $tempdir/np; f_printNPING; done; done; fi
}
f_printHOSTNAMES(){
local a="$*"; rr_hostnames=$(f_getHOSTNAMES); [[ -n "$rr_hostnames" ]] &&  echo -e "\n$a\n\n$rr_hostnames\n"
}
f_RECORD_DETAILS(){
[[ -f $tempdir/rr_hostnames ]] && rm $tempdir/rr_hostnames
echo ''; f_HEADLINE "$x | DNS RECORDS DETAILS"
if [ $domain_enum = "true" ]; then
if [ -f $tempdir/v4_uniq ] || [ -f $tempdir/v6_uniq ]; then
echo -e "\nDOMAIN & WEB HOST(S)"; if [ -f $tempdir/v4_uniq ]; then
for a in $(cat $tempdir/v4_uniq); do
echo ''; f_HOST_SHORT "$a"; f_printHOSTNAMES "$a" >> $tempdir/rr_hostnames; done; unset a; else
for z in $(cat $tempdir/v6_uniq); do
echo ''; f_HOST_SHORT "$z"; done; echo ''; fi; f_HEADLINE2 "NS RECORDS\n"; else
echo -e "\nNS RECORDS\n"; fi; else 
if [ -f $tempdir/dhostv4 ] || [ -f $tempdir/dhostv6 ]; then
echo -e "\nDOMAIN HOST"; if [ -f $tempdir/dhostv4 ]; then
for a in $(cat $tempdir/dhostv4); do
echo ''; f_HOST_SHORT "$a"; f_printHOSTNAMES "$a" >> $tempdir/rr_hostnames; done; unset a; else
for z in $(cat $tempdir/dhostv6); do
echo ''; f_HOST_SHORT "$z"; done; fi
f_HEADLINE2 "NS RECORDS\n"; else
echo -e "\nNS RECORDS\n"; fi; fi
if [ -f $tempdir/ns_ipv4.list ]; then
for a in $(cat $tempdir/ns_ipv4.list); do
f_HOST_SHORT "$a"; echo ''; done; else
for z in $(cat $tempdir/ns_ipv6.list); do
f_HOST_SHORT "$z"; echo ''; done; fi
if [ -f $tempdir/mx_hosts ]; then
f_HEADLINE2 "MX RECORDS\n"; if [ -f $tempdir/mx_ipv4.list ]; then
for a in $(cat $tempdir/mx_ipv4.list); do
f_HOST_SHORT "$a"; echo ''; f_printHOSTNAMES "$a" >> $tempdir/rr_hostnames; done; unset a
elif [ -f $tempdir/mx_ipv6.list ]; then
for z in $(cat $tempdir/mx_ipv6.list); do
f_HOST_SHORT "$z"; echo ''; done; unset z; fi; fi
if [ -f $tempdir/txt+srv ]; then
f_HEADLINE2 "SRV RECORDS\n"; for a in $(cat $tempdir/txt+srv); do
f_HOST_SHORT "$a"; echo ''; f_printHOSTNAMES "$a" >> $tempdir/rr_hostnames; done; unset a; rm $tempdir/srv_ip; fi 
if [ -f $tempdir/rr_hostnames ]; then
echo ''; f_HEADLINE "DNS RECORDS HOSTNAMES"; echo ''; cat $tempdir/rr_hostnames; fi
}
f_RFC1912(){
local s="$*"; soa_rec=$(dig soa +short $s); soa_host=$(echo "$soa_rec" | cut -d ' ' -f 1); f_HEADLINE2 "RFC 1912 CHECK\n"
${PATH_nmap} -sn -Pn ${soa_host} --script dns-check-zone --script-args=dns-check-zone.domain=$s 2>/dev/null | grep '|' |
tr -d '|_' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/dns-check-zone:/d' | sed '/DNS check results for domain:/d' | sed 's/^ *//' |
sed 's/^MX$/* MX/' | sed 's/^NS$/* NS/' | sed 's/^SOA$/* SOA/' | tr '[:space:]' ' ' | sed 's/* NS/\n\n* NS\n/' | sed 's/* MX/\n\n* MX\n/' |
sed 's/* SOA/\n\n* SOA\n/' | sed 's/PASS/\nPASS/g' | sed 's/FAIL/\nFAIL/g' | sed 's/SOA REFRESH //' | sed 's/SOA RETRY //' |
sed 's/SOA EXPIRE //' | sed 's/SOA MNAME entry check //' | sed 's/Recursive queries //' | sed 's/was within/within/' |
sed 's/Multiple name servers Server has/Multiple NS -/' | sed 's/DNS name server IPs are public/NS IPs -/' | sed 's/was NOT/ NOT /' |
sed 's/None of the servers allow recursive queries./Recursive queries not allowed/' | sed 's/Reverse MX A records //' |
sed 's/Missing nameservers reported by your nameservers /Missing NS reported by your NS - /' | sed 's/DNS server response //' |
sed 's/Missing nameservers/Missing NS/' | sed 's/parent/parent -/'  | sed 's/Zone serial numbers //' | sed '/./,$!d'; echo ''
}
f_SRV_REC(){
local s="$*"; unset srv_rec
if [ $option_connect != "0" ] ; then
srv_rec=$(nmap -Pn -sn --script dns-srv-enum --script-args dns-srv-enum.domain=$s 2>/dev/null | grep '|' | sed '/dns-srv-enum/d' |
sed '/Active Directory/{x;p;p;x;}' | sed '/APT/{x;p;p;x;}' | sed '/Autodiscover/{x;p;p;x;}' | sed '/Kerberos/{x;p;p;x;}' |
sed '/LDAP/{x;p;p;x;}' | sed '/Matrix/{x;p;p;x;}' | sed '/Minecraft/{x;p;p;x;}' | sed '/Mumble/{x;p;p;x;}' | sed '/SIP/{x;p;p;x;}' |
sed '/SMTP/{x;p;p;x;}' | sed '/POP/{x;p;p;x;}' | sed '/IMAP/{x;p;p;x;}' | sed '/TeamSpeak/{x;p;p;x;}' | sed '/XMPP/{x;p;p;x;}' |
sed '/prio/{x;p;x;}' | tr -d '|_' | sed 's/^ *//')
if [ -n "$srv_rec" ]; then
echo "$srv_rec" | grep -sE "^[0-9]{2,5}+/+tcp" | sed 's/\/tcp/;/' | awk '{print $1 $NF}' | sort -u | grep ';' > $tempdir/services
srv_hosts=$(echo "$srv_rec" | grep -E "*./tcp|*./udp" | awk '{print $NF}' | sort -u)
for h in $srv_hosts; do
dig ${dig_array[@]} $h; done > $tempdir/srv
f_HEADLINE2 "SRV RECORDS"; echo "$srv_rec"; echo -e "\n__________\n"
if [ -f $tempdir/srv ]; then
cat $tempdir/srv; f_EXTRACT_IP4 $tempdir/srv | tee -a $tempdir/txt+srv >> $tempdir/rec_ips.list; rm $tempdir/srv; fi; fi; fi 
}
f_TTL_ALT(){
dom_v4_ttlu=$(dig ${nssrv_dig} +noall +answer +ttlunits $x); dom_v6_ttlu=$(dig ${nssrv_dig} aaaa +noall +answer +ttlunits $x)
mx_ttlu=$(dig ${nssrv_dig} mx +noall +answer +ttlunits $x); f_HEADLINE2 "TTL - HUMAN READABLE\n"
[[ -n "$dom_v4_ttlu" ]] && echo -e "\n$dom_v4_ttlu"; [[ -n "$dom_v6_ttlu" ]] && echo -e "\n$dom_v6_ttlu"
[[ -n "$mx_ttlu" ]] && echo -e "\n$mx_ttlu"; echo ''; dig ${nssrv_dig} ns +noall +answer +ttlunits $x; echo ''
}
#++++++ MX RECORDS ++++++
f_MX(){
local s="$*"; dig mx ${dig_array[@]} ${ttl} ${s} | rev | cut -c 2- | rev > $tempdir/mx.list
mxs=$(awk '{print $NF}' $tempdir/mx.list); echo ''; f_Long; echo -e "\nMX SERVERS"
if [ -n "$mxs" ]; then
[[ $dns_lod = "1" ]] && echo ''
awk '{print $4,$5}' $tempdir/mx.list | tr [:upper:] [:lower:] | sort -t ' ' -k 1 | awk '{print $NF}' > $tempdir/mx_hosts
for mx in $mxs; do
if [ $dns_lod = "1" ]; then
echo ''; grep -w -m 1 "$mx" $tempdir/mx.list | awk '{print $2"\t\t"$4,$5"\t\t"}' | tr '[:space:]' ' '
dig @1.1.1.1 +short $mx | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' |
tee -a $tempdir/mx4.list | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n -u | tr '[:space:]' ' '
dig @1.1.1.1 aaaa +short $mx | grep ':' | tee -a $tempdir/mx6.list | tr '[:space:]' ' '; echo -e "\n"; else
echo -e "\n"; grep -w -m 1 "$mx" $tempdir/mx.list | awk '{print $2"\t\t\t"$4,$5}'; echo ''
dig a ${dig_array[@]} ${ttl} $mx | grep -w 'A' | tee -a $tempdir/mx4.list | awk '{print $2"\t\t\t"$4}'
dig aaaa ${dig_array[@]} ${ttl} $mx | grep -w 'AAAA' | tee -a $tempdir/mx6.list | awk '{print $2"\t\t\t"$4}'; fi; done
if [ -f $tempdir/mx4.list ]; then
egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/mx4.list |
sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n -u | tee -a $tempdir/rec_ips.list > $tempdir/mx_ipv4.list; rm $tempdir/mx4.list; fi
if [ -f $tempdir/mx6.list ]; then
awk '{print $NF}' $tempdir/mx6.list | tee $tempdir/mx_ipv6.list >> $tempdir/rec_ips6.list; rm $tempdir/mx6.list; fi; else
echo -e "\nNo MX records found"; fi
}
f_MX_CERTS(){
highest_prio=$(head -1 $tempdir/mx_hosts); f_CERT_INFO "$highest_prio"; echo ''
sort -u $tempdir/mx_hosts | sed '/^$/d' > $tempdir/mx_hosts_sorted
mx_hosts_sorted=$(grep -v $highest_prio $tempdir/mx_hosts_sorted)
if [ -f $tempdir/SANs ]; then
for m in $mx_hosts_sorted; do
[[ $(grep -c "$m" $tempdir/SANs) = 0 ]] && f_CERT_INFO "$m" && echo ''; done; else
for m in $mx_hosts_sorted; do
f_CERT_INFO "$m"; echo ''; done; fi
}
f_MX_CHECK(){
if [ -f $tempdir/mx_ipv4.list ]; then
echo ''; f_Long; echo -e "\nChecking DNS (SPAM) blocklists for domain MX records ...\n"; f_BLOCKLIST_CHECK "$tempdir/mx_ipv4.list"; fi
}
#++++++ NS RECORDS ++++++
f_AUTHNS_PTR(){
f_HEADLINE2 "AUTH NS  (REV. LOOKUP ZONES)"
if [ -f $tempdir/zone_lookups4 ]; then
for a in $(grep -sEo "$REGEX_IP4" $tempdir/zone_lookups4); do
a_trimmed=$(echo "$a" | cut -d '.' -f -2 | tr -d ' ')
ips_all=$(grep "$a_trimmed" $tempdir/rec_ips.list | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n -u | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//'; echo '')
echo -e "\n\n>  $ips_all\n"; f_getAUTHNS_PTR "$a"; done; fi
}
f_getAUTHNS_PTR(){
unset rdns_ns; rr_address=$(grep -sEo "$REGEX_IP4" <<< $1)
if [ -n "$rr_address" ]; then
dig @1.1.1.1 +noall +answer +trace +nocrypt +noclass -x $rr_address > $tempdir/trace
if [ -f $tempdir/trace ]; then
rdns_ns=$(sed -e '/./{H;$!d;}' -e 'x;/PTR/!d' $tempdir/trace | grep -E "NS|^;;" | cut -d '(' -f 2 | cut -d ')' -f 1 | rev | awk '{print $1}' | sed 's/^\.//' | rev | sort -uV); [[ -z "$rdns_ns" ]] && rdns_ns=$(tail -3 $tempdir/trace | grep -E "^;;" | cut -d '(' -f 2 | cut -d ')' -f 1  | tr -d ' ')
[[ -n "$rdns_ns" ]] && print_ns=$(echo "$rdns_ns" | tr '[:space:]' ' ' | sed 's/^ *//' | fmt -w 60 | sed G) && echo -e "$print_ns" | sed 's/^/   /'; fi; fi
}
f_NS(){
local s="$*"; dig ns ${dig_array[@]} ${ttl} $s | rev | cut -c 2- | rev > $tempdir/ns.list
awk '{print $NF}' $tempdir/ns.list > $tempdir/ns_servers; echo ''; f_Long; echo -e "\nNAME SERVERS"
[[ $dns_lod = "1" ]] && echo ''; for ns in $(cat $tempdir/ns_servers); do
if [ $dns_lod = "1" ]; then
echo ''; grep -w "${ns}" $tempdir/ns.list | awk '{print $2"\t\t"$4"\t\t"}' | tr '[:space:]' ' '
dig @1.1.1.1 +short $ns | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' |
tee -a $tempdir/ns4.list | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n -u | tr '[:space:]' ' '
dig @1.1.1.1 aaaa +short $ns | grep ':' | tee -a $tempdir/ns6.list | tr '[:space:]' ' '; echo ''; else
echo -e "\n"; grep -w "${ns}" $tempdir/ns.list | awk '{print $2"\t\t\t"$4}'; echo ''
dig ${dig_array[@]} ${ttl} $ns | grep -w 'A' | tee -a $tempdir/ns4.list | awk '{print $2"\t\t\t"$4}'
dig aaaa ${dig_array[@]} ${ttl} $ns | grep -w 'AAAA' | tee -a $tempdir/ns6.list | awk '{print $2"\t\t\t"$4}'; fi; done
if [ -f $tempdir/ns4.list ]; then
egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/ns4.list |
sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n -u | tee $tempdir/ns_ipv4.list >> $tempdir/rec_ips.list; fi
if [ -f $tempdir/ns6.list ]; then
awk '{print $NF}' $tempdir/ns6.list | tee $tempdir/ns_ipv6.list >> $tempdir/rec_ips6.list; rm $tempdir/ns6.list; fi
}
f_NS_DETAILS(){
echo ''; f_Long; echo -e "\nNSEC/NSEC3 / VERSION.BIND\n"
for n in $(cat $tempdir/ns_servers); do
bindvers=$(dig @${n} version.bind txt chaos +norecurse +noedns +short | tr -d '"' | sed 's/^ *//' |
sed 's/;; connection timed out; no servers could be reached/connection timed out/g' | grep -E -v "^;|^;;" | sed '/^$/d')
echo -e "\n$n\n"; [[ $(echo "$bindvers" | wc -w) = 0 ]] && echo "  Version.BIND:   NA" || echo "  Version.BIND:   $bindvers"
f_NSEC "${n}"; done; echo ''
}
f_NSEC(){
local s="$*"
nsec=$(host -t nsec ${s} 1.1.1.1 | tail -1 | fmt -s -w 80); nsec3=$(host -t nsec3 ${s} 1.1.1.1 | tail -1 | fmt -s -w 80)
if echo "$nsec" | grep -q 'has no'; then
nsec_rec="false"; else
nsec_rec="true"; fi
if echo "$nsec3" | grep -q 'has no'; then
nsec3_rec="false"; else
nsec3_rec="true"; fi
if [ $nsec_rec = "false" ] && [ $nsec3_rec = "false" ]; then
echo "  NSEC/NSEC3:     no"; else
[[ $nsec_rec = "false" ]] && echo "  NSEC:           no" || echo -e "  NSEC:\n  $nsec\n"
[[ $nsec3_rec = "false" ]] && echo "  NSEC3:          no" || echo -e "  NSEC3:\n  $nsec3\n"; fi
}
f_SOA(){
local s="$*"; f_HEADLINE2 "START OF AUTHORITY\n"; dig ${nssrv_dig} soa +noall +answer +multiline $s > $tempdir/soa.txt
dig ${nssrv_dig} soa +noall +answer +noclass +ttlid $s | awk '{print $2,$3,$4,$5}' | sed 's/ /\t/g' ; echo ''
grep -E "; serial|; refresh|; retry|; expire|; minimum" $tempdir/soa.txt | awk '{print $3":",$1,$4,$5,$6,$7}' | sed 's/:/: /g' |
sed 's/serial:/serial: /' | sed 's/retry:/retry:  /' | sed 's/expire:/expire: /' | sed '/serial:/{x;p;x;G}'
}

#-------------------------------  SUBDOMAINS  -------------------------------

f_SUBS(){
curl -s -m 30 https://api.hackertarget.com/hostsearch/?q=$1${api_key_ht} |
egrep -s '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' > $tempdir/ht_raw
if [ -f $tempdir/ht_raw ] && [[ $(wc -l < $tempdir/ht_raw) -gt 2 ]]; then
grep ',' $tempdir/ht_raw | sort -u | tee $tempdir/subs_tmp > $tempdir/results_ht
cut -s -d ',' -f 1 $tempdir/results_ht | tr -d ' ' | sort -u > $tempdir/hosts_ht
sort -t ',' -k 1 $tempdir/results_ht | sed 's/,/ => /' | awk '{print $3 "\t\t" $2 "\t" $1}' > $tempdir/subs_ht
f_HEADLINE "$1  SUBDOMAINS (IPV4) | $file_date  [Source: hackertarget.com]" > ${outdir}/Subdomains_HT.${1}.txt
echo '' >> ${outdir}/Subdomains_HT.${1}.txt; cat $tempdir/subs_ht >> ${outdir}/Subdomains_HT.${1}.txt; fi
[[ -f $tempdir/rr_hostnames ]] && cat $tempdir/rr_hostnames > $tempdir/hosts
[[ -f $tempdir/dnsnames ]] && [[ $(wc -w < $tempdir/dnsnames) -gt 0 ]] && cat $tempdir/dnsnames >> $tempdir/hosts
[[ $option_subs = "2" ]] && [[ -f $tempdir/hosts_ht ]] && cat $tempdir/hosts_ht >> $tempdir/hosts
[[ -f  $tempdir/hosts ]] && f_RESOLVE_HOSTS4 "$tempdir/hosts" >> $tempdir/subs_tmp
if [ -f $tempdir/subs_tmp ] && [[ $(grep -c ',' $tempdir/subs_tmp) -gt 0 ]]; then
egrep -s -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/subs_tmp >> $tempdir/ips.list
sort -bifu $tempdir/subs_tmp | sort -t ',' -k 1 | sed 's/,/ => /' |
awk '{print $3 "\t\t" $2 "\t" $1}' > $tempdir/subs4
f_HEADLINE "$s  SUBDOMAINS (IPV4),  $file_date" > $tempdir/print_subs; echo '' >> $tempdir/print_subs
cat $tempdir/subs4 >> $tempdir/print_subs; echo '' >> $tempdir/print_subs
cat $tempdir/print_subs > ${outdir}/SUBDOMAINS_${x}.txt; fi
if [ -f $tempdir/subs6 ]; then
f_HEADLINE "$s  SUBDOMAINS (IPV4) | $file_date  [Source: hackertarget.com]" >> ${outdir}/SUBDOMAINS_V6.${1}.txt
echo '' >> ${outdir}/SUBDOMAINS_V6.${1}.txt
cat $tempdir/subs6 >> ${outdir}/SUBDOMAINS_V6.${1}.txt; fi
}
f_SUBS_HEADER(){
echo -e "\n"; f_HEADLINE "SUBDOMAINS - NETWORKS & ORGANISATIONS"
echo -e "\nSearching for hosts/subdomains...\n"; f_SUBS "$x"; subcount=$(f_countL "$(sort -uV $tempdir/ips.list)")
echo -e "\nFound $subcount unique IPv4 hosts within the following resources:\n\n"
sort -t . -k 1,1n -k 2,2n -k 3,3n -u $tempdir/ips.list > $tempdir/ips_sorted.list; f_whoisTABLE "$tempdir/ips_sorted.list"
if [ -f $tempdir/whois_table.txt ]; then
grep -E "^[0-9]" $tempdir/whois_table.txt | grep -w -v 'NA' | sed '/^$/d' | sort -t . -k 1,1n -k 2,2n -u > $tempdir/table_sorted1
grep -E "^[0-9]" $tempdir/whois_table.txt | grep -w -v 'NA' | sed '/^$/d' | sort -t '|' -k 5 -u >> $tempdir/table_sorted1
cat $tempdir/table_sorted1 | awk -F '|' '{print $1,$3,$4,$5,$2}' OFS='|' | rev | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n -u |
cut -d '.' -f 3- | rev | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/$/.x.x/g' | sort -t '|' -k 4 -V > $tempdir/whois_table2
grep -E "^[0-9]" $tempdir/whois_table.txt | grep -w 'NA' | sort -t . -k 1,1n -k 2,2n -u >> $tempdir/table_sorted11
cat $tempdir/table_sorted11 | awk -F '|' '{print $1,$3,$4,$5,$2}' OFS='|' | rev | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n -u |
cut -d '.' -f 3- | rev | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/$/.x.x/g' | sort -t '|' -k 4 -V >> $tempdir/whois_table2; fi
if [ -f $tempdir/whois_table2 ]; then
cut -d '|' -f -2 $tempdir/whois_table.txt | grep -E "^[0-9]" | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' |
sort -uV > $tempdir/ips_sorted2.list; f_pwhoisBULK "$tempdir/ips_sorted2.list"
cut -d '|' -f -2 $tempdir/whois_table.txt | grep -E "^NA" | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' |
sort -uV > $tempdir/no_as.list
asnums=$(cut -d '|' -f 1 $tempdir/whois_table2 | tr -d ' ' | sed '/^$/d' | sort -ug)
grep 'ORG NAME' $tempdir/whois_table.txt | awk -F '|' '{print $1,$3,$4,$5,$2}' OFS='|'; echo ''; cat $tempdir/whois_table2
if [ -f $tempdir/cert_mail ] && [[ $(grep -c '@' $tempdir/cert_mail) -gt 0 ]]; then
echo ''; f_Long; echo -e "\nCERTIFICATE E-MAIL ADDRESSES  (DOMAIN CERTIFICATE ISSUANCES)\n\n"; cat $tempdir/cert_mail; fi
if [ -f $tempdir/no_as.list ]; then
for n in $(cat $tempdir/no_as.list); do
f_BOGON "$n"
[[ $bogon = "TRUE" ]] && echo $n >> $tempdir/bogons || echo $n >> $tempdir/v4_no_as; done
if [ -f $tempdir/bogons ]; then
echo ''; f_Long; echo -e "IPv4 BOGONS\n\n"
for b in $(cat $tempdir/bogons | sort -uV); do
bogon_sub=$(grep -w "${b}" $tempdir/subs4)
echo "$bogon_sub"; done; echo ''; fi
if [ -f $tempdir/v4_no_as ]; then
echo -e "\nNOT ANNOUNCED\n"
cat $tempdir/v4_no_as | sed 's/^[ \t]*//;s/[ \t]*$//' | sed G | fmt -w 55; fi; fi
echo ''; f_Long; echo -e "\nAUTONOMOUS SYSTEMS\n"
for as in $asnums; do
echo ''; f_AS_SHORT "${as}"; done
if [ -f $tempdir/lacnic_asns ]; then
lacnic_asns=$(sort -ug $tempdir/lacnic_asns | sed 's/^/|/' | tr '[:space:]' ' ' | sed 's/^|//' | grep '|' | tr -d ' '); fi
if [ -n "$lacnic_asns" ]; then
grep -E -v "$lacnic_asns" $tempdir/pwhois | grep '|' | awk -F '|' '{print $1,$3,$5}' OFS='|' |
sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n | sort -t '|' -k 3 -V | sed '/^$/d' > $tempdir/net_table
grep -E "$lacnic_asns" $tempdir/pwhois | awk -F'|' '{print $3,"~",$4}' | sed 's/^ *//' |
sort -t '~' -k 1 -u | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n -u > $tempdir/lacnic_nets
sort -t '~' -k 2 -u $tempdir/lacnic_nets | cut -s -d '~' -f 1 | tr -d ' ' | sort -t . -k 1,1n -k 2,2n -k 3,3 -k 4,4 -u > $tempdir/poc_lookups; else
grep '|' $tempdir/pwhois | awk -F '|' '{print $1,$3,$5}' OFS='|' |
sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n | sort -t '|' -k 3 -V | sed '/^$/d' > $tempdir/net_table; fi
grep -w -v 'NA' $tempdir/net_table | cut -s -d '|' -f 3 | sed 's/^[ \t]*//;s/[ \t]*$//' | sort -uV > $tempdir/nets_uniq
grep -w 'NA' $tempdir/pwhois | cut -s -d '|' -f 3 > $tempdir/no_netname
for t in $(cat $tempdir/nets_uniq); do
grep -E -w ${t} $tempdir/net_table | cut -d '|' -f 1 | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' |
head -1; done > $tempdir/net_lookup.list
egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/no_netname | sort -uV >> $tempdir/net_lookup.list; fi
}

#-------------------------------  SSL/TLS  -------------------------------

f_CERT_INFO(){
local s="$*"; if [ $option_connect != "0" ]; then
unset ocsp_response; unset cert_status; unset stapling_response; unset self_signed; unset dns_caa
unset cert_serial; unset verify_ok; unset vrfy_code; unset vrfy_code1; unset vrfy_code2
[[ -f $tempdir/x509 ]] && rm $tempdir/x509; [[ -f $tempdir/brief ]] && rm $tempdir/brief; [[ -f $tempdir/ssl ]] && rm $tempdir/ssl
[[ -f $tempdir/ocsp_tmp ]] && rm $tempdir/ocsp_tmp; [[ -f $tempdir/ossl ]] && rm $tempdir/ossl
host_addresses=$(host $s | grep -E "has address|has IPv6 address" | awk '{print $NF}' | sort -u)
host_addresses_v4=$(f_EXTRACT_IP4 "$host_addresses"); host_addresses_v6=$(f_EXTRACT_IP6 "$host_addresses")
printv4=$(f_printADDR "$host_addresses_v4"); printv6=$(f_printADDR "$host_addresses_v6"); dns_caa=$(dig @1.1.1.1 +short caa $s)
if [ $option_starttls = "0" ]; then
echo | timeout 10 openssl s_client -connect $s:$tls_port -brief 2>$tempdir/brief
if [[ $(grep -c 'CONNECTION ESTABLISHED' $tempdir/brief) = 1 ]]; then
echo | timeout 10 openssl s_client -connect $s:$tls_port 2>/dev/null | openssl x509 -text -nameopt multiline -fingerprint -sha256 |
sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/[Ss]ubject:/\n\nSubject:/' |  sed 's/[Ii]ssuer:/\n\nIssuer:/' |
sed '/commonName/G' | sed '/X509v3 [Ee]xtensions:/{x;p;x;}' > $tempdir/x509; fi; else
target_ip=$(dig +short $s | head -1)
if [ -n "$target_ip" ]; then
if [ $option_starttls = "1" ]; then
echo | timeout 3 openssl s_client -starttls smtp -connect $target_ip:25 -servername $s -brief 2>$tempdir/brief
[[ $(grep -c 'CONNECTION ESTABLISHED' $tempdir/brief) = 1 ]] && stls_port=25; stls_pro=smtp
elif [ $option_starttls = "2" ]; then
echo | timeout 3 openssl s_client -starttls imap -connect $target_ip:993 -servername $s -brief 2>$tempdir/brief
if [[ $(grep -c 'CONNECTION ESTABLISHED' $tempdir/brief) = 1 ]]; then
stls_port=993; stls_pro=imap; else
echo | timeout 3 openssl s_client -starttls imap -connect $target_ip:143 -servername $s -brief 2>$tempdir/brief
if [[ $(grep -c 'CONNECTION ESTABLISHED' $tempdir/brief) = 1 ]]; then
stls_port=143; stls_pro=imap; fi; fi
elif [ $option_starttls = "3" ]; then
echo | timeout 3 openssl s_client -starttls pop3 -connect $target_ip:995 -servername $s -brief 2>$tempdir/brief
if [[ $(grep -c 'CONNECTION ESTABLISHED' $tempdir/brief) = 1 ]]; then
stls_port=995; stls_pro=pop3; else
echo | timeout 3 openssl s_client -starttls pop3 -connect $target_ip:110 -servername $s -brief 2>$tempdir/brief
if [[ $(grep -c 'CONNECTION ESTABLISHED' $tempdir/brief) = 1 ]]; then
stls_port=110; stls_pro=pop3; fi; fi; fi
if [ -n "$stls_port" ]; then
echo | timeout 10 openssl s_client -starttls $stls_pro -connect $target_ip:$stls_port -servername $s 2>/dev/null | openssl x509 -text -fingerprint -sha256 -nameopt multiline  |
sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/[Ss]ubject:/\n\nSubject:/' | sed 's/[Ii]ssuer:/\n\nIssuer:/' | sed '/commonName/G' |
sed '/X509v3 [Ee]xtensions:/{x;p;x;}' > $tempdir/x509; fi; fi; fi
exp=$(grep -sEi -A 3 "^Validity" $tempdir/x509 | grep -sEi -m 1 "Not After|NotAfter" | cut -d ':' -f 2- | cut -d '=' -f 2- |
sed 's/^[ \t]*//;s/[ \t]*$//')
if [ -n "$exp" ]; then
echo ''; protocol=$(grep -E "^Protocol version:" $tempdir/brief | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
cipher=$(grep -E "^Ciphersuite:" $tempdir/brief | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
tmp_key=$(grep -E "^Server Temp Key:" $tempdir/brief | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
ex_date=$(echo $exp | awk '{print $1,$2,$4,"("$3,$5")"}')
start_date=$(grep -Ei -A 3 "^Validity" $tempdir/x509 | grep -sEi -m 1 "^Not Before|NotBefore" | cut -d ':' -f 2- | cut -d '=' -f 2- |
sed 's/^[ \t]*//;s/[ \t]*$//' | awk '{print $1,$2,$4}')
s_cn=$(sed -e '/./{H;$!d;}' -e 'x;/Subject:/!d;' $tempdir/x509 | grep -iw -m 1 'commonName' | cut -d '=' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
s_cc=$(sed -e '/./{H;$!d;}' -e 'x;/Subject:/!d;' $tempdir/x509 | grep -iw -m 1 'countryName' | cut -d '=' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
s_org=$(sed -e '/./{H;$!d;}' -e 'x;/Subject:/!d;' $tempdir/x509 | grep -iw -m 1 'organizationName' | cut -d '=' -f 2- |
sed 's/^[ \t]*//;s/[ \t]*$//')
ca_cn=$(sed -e '/./{H;$!d;}' -e 'x;/Issuer:/!d;' $tempdir/x509 | grep -iw -m 1 'commonName' | cut -d '=' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
ca_cc=$(sed -e '/./{H;$!d;}' -e 'x;/Issuer:/!d;' $tempdir/x509 | grep -iw -m 1 'countryName' | cut -d '=' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
ca_org=$(sed -e '/./{H;$!d;}' -e 'x;/Issuer:/!d;' $tempdir/x509 | grep -iw -m 1 'organizationName' | cut -d '=' -f 2- |
sed 's/^[ \t]*//;s/[ \t]*$//')
serial=$(grep -A 1 "Serial Number:" $tempdir/x509 | tail -1 | sed 's/://g' | tr [:lower:] [:upper:] | grep -v 'SIGNATURE')
cert_sha=$(grep -i 'SHA256 Fingerprint=' $tempdir/x509 | cut -s -d '=' -f 2- | sed 's/://g' | tr [:upper:] [:lower:] | sed 's/^ *//')
sign=$(grep -E -m 1 "^Signature Algorithm:" $tempdir/x509 | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/sha/SHA/' |
sed 's/With/ with /')
pubky=$(grep -sEi "^Public Key Algorithm:|^Public-Key:|^ASN1 OID:|^NIST CURVE:" $tempdir/x509 | sed 's/bit)/bit) \//' |
cut -s -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//'  | tr '[:space:]' ' ' ; echo '')
print_altnames=$(grep 'DNS:' $tempdir/x509 | sed 's/DNS:/\n/g' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' |
tr '[:space:]' ' ' | fmt -s -w 70)
sed -n '/-----BEGIN/,/-----END/p' $tempdir/x509 > $tempdir/leaf.crt
if [ $option_starttls = "0" ]; then
echo | timeout 7 openssl s_client -connect $s:$tls_port 2>/dev/null -status -showcerts -verify_hostname $s > $tempdir/ossl; else
echo | timeout 7 openssl s_client -starttls $stls_pro -connect $target_ip:$stls_port -servername $s 2>/dev/null -status -showcerts -verify_hostname $s > $tempdir/ossl; fi
vrfy_code=$(grep 'Verify return code:' $tempdir/ossl | cut -d ':' -f 2- | cut -d '(' -f 1 | tr -d ' ')
[[ $vrfy_code -eq 0 ]] && verify_ok="true" || verify_ok="false"; [[ $vrfy_code -eq 18 ]] && self_signed="true" || self_signed="false"
if [ $verify_ok = "true" ]; then
verify=$(grep -Eiw -B 1 "^Verified peername:" $tempdir/ossl | grep 'Verification:' | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
verify_name=$(grep -Eiw "^Verified peername:" $tempdir/ossl | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
verify_code=$(grep 'Verify return code:'  $tempdir/ossl | cut -d ':' -f 2- | cut -d '(' -f 1 | tr -d ' ')
verify_message=$(grep 'Verify return code:'  $tempdir/ossl | sed 's/^[ \t]*//;s/[ \t]*$//'); fi
pubky_length=$(grep 'Server public key' $tempdir/ossl | awk -F'is' '{print $NF}' | sed 's/^[ \t]*//;s/[ \t]*$//')
subject_hash=$(openssl x509 -in $tempdir/leaf.crt -noout -subject_hash); num_certs=$(grep -c "END CERTIFICATE" $tempdir/ossl)
if [ $option_testssl != "1" ]; then
if  [ $vrfy_code != "18" ] && [ $vrfy_code != "21" ]; then
ocsp_uri=$(openssl x509 -noout -ocsp_uri -in $tempdir/leaf.crt)
stapling_resp=$(grep -A 4 "^OCSP response:" $tempdir/ossl | grep -wi "OCSP Response Status:" | cut -d ':' -f 2- |
cut -d '(' -f 1 | tr -d ' ')
if [ -n "$stapling_resp" ] && [[ $stapling_resp =~ "successful" ]]; then
stapling="true"; sed -n '/OCSP Response Data:/,/Next Update:/p' $tempdir/ossl > $tempdir/ocsp; else
stapling="false"; if [[ $num_certs -gt 1 ]]; then
sed -n '/Certificate chain/,/-----END CERTIFICATE/!p' $tempdir/ossl | sed -n '/-----BEGIN/,/-----END/p' > $tempdir/chain.crt
openssl ocsp -issuer $tempdir/chain.crt -cert $tempdir/leaf.crt -url $ocsp_uri -text 2>$tempdir/ocsp >> $tempdir/ocsp; fi; fi
if [ -f $tempdir/ocsp ]; then
response_status=$(grep -iw -m 1 'OCSP Response Status:' $tempdir/ocsp | cut -d ':' -f 2- | cut -d '(' -f 1 | sed 's/^[ \t]*//;s/[ \t]*$//')
cert_status=$(grep -iw 'Cert Status:' $tempdir/ocsp | sed 's/^[ \t]*//;s/[ \t]*$//'); fi; fi; fi
if [ $quiet_dump = "true" ]; then
if [ $option_starttls = "0" ]; then
echo -e "Downloading cert files from $s:$tls_port ..."; else
echo -e "Downloading cert files from $s ($target_ip:$stls_port) ..."; fi; fi
[[ $verify_ok = "true" ]] && ver_status="$verify" || ver_status="ERROR"
if ! [ $option_starttls = "0" ] ; then
echo -e "\n"; f_Long; echo "[SSL]  $s  | $stls_pro/$stls_port | STATUS: $ver_status"; f_Long; else
echo -e "\n"; f_Long; echo "[SSL]  $s  | PORT: $tls_port | STATUS: $ver_status"; f_Long; fi
if [ $target_type = "web" ]; then
if [ $option_www = "4" ]; then
if [[ $(echo "$host_addresses" | wc -w) -lt 4 ]]; then
echo -e "\nDNS:           $printv4 $printv6\n" > $tempdir/ssl; else
echo -e "\nDNS:           $printv4\n" > $tempdir/ssl
[[ -n "$printv6" ]] && echo -e "               $printv6\n" >> $tempdir/ssl; f_Long >> $tempdir/ssl; fi; fi; fi
if [ -n "$s_org" ] ; then
echo -e "\nSubject:       $s_cn  ($s_org, $s_cc)\n" >> $tempdir/ssl; else
echo -e "\nSubject:       $s_cn  $s_cc\n" >> $tempdir/ssl; fi
if [ -n "$verify_code" ]; then
if [[ $verify_code -eq 0 ]]; then
echo -e "Verify:        $verify  ($verify_name)" >> $tempdir/ssl; else
echo -e "Verify:        $verify_message  ($verify_name)" >> $tempdir/ssl; fi; fi
echo -e "\nValid:         $start_date  -  $ex_date" >> $tempdir/ssl
if [ $option_testssl != "1" ] && [ -f $tempdir/ocsp ]; then
[[ -n "$dns_caa" ]] || echo ''; if [ -n "$cert_status" ]; then
echo -e "\nOCSP:          $cert_status | Stapling: $stapling | URL: $ocsp_uri" >> $tempdir/ssl; else
echo -e "\nOCSP:          Response: $response_status;  URL: $ocsp_uri" >> $tempdir/ssl; fi; fi
[[ -n "$dns_caa" ]] || echo -e "\nDNS CAA:       No CAA record\n" >> $tempdir/ssl
echo '' >> $tempdir/ssl; f_Long >> $tempdir/ssl
echo -e "Issuer:        $ca_cn  ($ca_org, $ca_cc)" >> $tempdir/ssl; f_Long >> $tempdir/ssl
echo -e "\nSerial:        $serial" >> $tempdir/ssl
if [[ $(f_countW "$host_addresses") -lt 2 ]] || [ $target_type = "web" ]; then
echo -e "\nCert SHA256:   $cert_sha" >> $tempdir/ssl; fi
echo -e "\nSignature:     $sign\n" >> $tempdir/ssl
echo -e "\nPubKey:        $pubky ($pubky_length)" >> $tempdir/ssl
echo -e "\nProto/Cipher:  $protocol | $cipher | $tmp_key\n" >> $tempdir/ssl
[[ $quiet_dump = "false" ]] && cat $tempdir/ssl
echo '' > $tempdir/print_cert; f_HEADLINE "$s | CERTIFICATE FILE DUMP | $file_date" >> $tempdir/print_cert
cat $tempdir/ssl >> $tempdir/print_cert
[[ $(f_countW "$host_addresses") -gt 1 ]] && echo -e "\nCert SHA256:  $cert_sha" >> $tempdir/print_cert
if [ $quiet_dump = "false" ]; then
if [[ $(f_countW "$host_addresses") -gt 1 ]] && [ $target_type != "web" ]; then
f_HEADLINE2 "CERTIFICATE SHA 256"
for i in $host_addresses; do
if [ $option_starttls = "0" ]; then
echo | timeout 3 openssl s_client -connect [$i]:$tls_port -servername $s 2>/dev/null |
openssl x509 -noout -nocert -nameopt multiline -subject -fingerprint -sha256 > $tempdir/sha256; else
echo | timeout 3 openssl s_client -starttls $stls_pro -connect [$i]:$stls_port -servername $s 2>/dev/null |
openssl x509 -noout -nocert -nameopt multiline -subject -fingerprint -sha256 > $tempdir/sha256; fi
coname=$(grep -i 'commonName' $tempdir/sha256 | cut -d '=' -f 2- | sed 's/^ *//')
cert_sha=$(grep -i 'SHA256 Fingerprint=' $tempdir/sha256 | cut -s -d '=' -f 2- | sed 's/://g' | tr [:upper:] [:lower:] | sed 's/^ *//')
echo "$i | $coname | $cert_sha"; done > $tempdir/sha256_compare
sha_diff=$(sort -t '|' -k 2 -u $tempdir/sha256_compare)
if [[ $(f_countL "$sha_diff" ) -gt 1 ]]; then 
echo ''; cat $tempdir/sha256_compare | sed '/|/G'; else
print_cert_sha=$(cut -d '|' -f 3 $tempdir/sha256_compare | tr -d ' ' | sort -u)
echo -e "\n$print_cert_sha\n\nMATCHED BY HOSTS:\n"
[[ -n "host_addresses_v4" ]] && echo -e "$(f_printADDR "$host_addresses_v4")"
[[ $(f_countW "$host_addresses_v6") -gt 0 ]] && echo -e "$(f_printADDR "$host_addresses_v6")"; fi; fi
if [ -n "$dns_caa" ]; then
[[ $target_type != "web" ]] && [[ $(f_countW "$host_addresses") -eq 1 ]] && echo ''
f_Long; echo -e "DNS CAA\n\n$dns_caa"; fi
if [ -n "$print_altnames" ]; then
f_Long; echo -e "\nSUBJECT ALT.NAMES\n\n$print_altnames"; fi; fi
echo '' >> $tempdir/print_cert; f_Long >> $tempdir/print_cert
sed -n '/Certificate chain/,/Server certificate/p' $tempdir/ossl | sed 's/s:/Holder: /g' | sed 's/i:/Issuer: /g' | sed '/END/G' |
sed '/BEGIN/{x;p;x}' | sed '$d' | sed 's/Certificate chain/\nCERTIFICATE CHAIN\n/' >> $tempdir/print_cert
echo '' >> $tempdir/print_cert; sed -n '/X509v3 extensions:/,/SHA256/p' $tempdir/x509 |
sed '$d' | sed '/Subject Key Identifier:/{x;p;x;}' | sed '/Policies:/{x;p;x;}' | sed '/Subject OCSP/{x;p;x;}' |
sed '/SCTs/{x;p;x;}' | sed '/SHA256/d' | sed '/Signature Algorithm:/{x;p;x;G}' | sed '/Timestamp:/{x;p;x;}' |
sed '/Constraints:/{x;p;x;}' | sed '/extensions:/{x;p;x;}' | sed '/Policies:/{x;p;x;}' |
sed '/Alternative Name:/{x;p;x;G}' >> $tempdir/print_cert
if [ $option_starttls != "0" ]; then
sed -n '/X509v3 Subject Alternative Name:/,/X509v3 Certificate Policies:/p' $tempdir/x509 | grep 'DNS:' |
sed 's/DNS:/\n/g' | tr -d ',' | tr [:upper:] [:lower:] | sort -u | sed '/^$/d' >> $tempdir/SANs; fi
[[ $option_starttls = "0" ]] && cat $tempdir/print_cert > ${outdir}/CERT.${s}.txt
[[ $option_starttls = "1" ]] && cat $tempdir/print_cert > ${outdir}/CERT_SMTP.${s}.txt
[[ $option_starttls = "2" ]] && cat $tempdir/print_cert > ${outdir}/CERT_IMAP.${s}.txt
[[ $option_starttls = "3" ]] && cat $tempdir/print_cert > ${outdir}/CERT_POP3.${s}.txt
[[ $option_testssl = "1" ]] && f_RUN_TESTSSL "$s"; else
echo -e "\nNo certificate found for $s.\n"; fi; fi
}
f_CERT_SPOTTER(){
local s="$*"; dnsnames=''
if [ $include_subdomains = "true" ]; then
curl -s -m 7 "https://api.certspotter.com/v1/issuances?domain=${s}&include_subdomains=true&expand=dns_names&expand=issuer&expand=cert" > $tempdir/certs.json
else
curl -s -m 7 "https://api.certspotter.com/v1/issuances?domain=${s}&expand=dns_names&expand=issuer&expand=cert" > $tempdir/certs.json; fi
if [ -f $tempdir/certs.json ]; then
dnsnames=$(jq -r '.[].dns_names | .[]' $tempdir/certs.json)
if [ $include_subdomains = "true" ]; then
echo ''; f_HEADLINE "$s  DOMAIN CERTIFICATE ISSUANCES [certspotter.com]  $file_date"; else
f_HEADLINE2 "$s SSL"; fi
if [ -n "$dnsnames" ]; then
issuances=$(jq -r '.[] | {Subject: .dns_names[], Issuer: .issuer.name, Issued: .not_before, Expires: .not_after, CertSHA256: .cert.sha256}' $tempdir/certs.json |
tr -d '}"{,' | sed 's/^ *//' | sed '/^$/d' | sed 's/C=/\nC: /g' | sed 's/ST=/\nST=/g' | sed 's/L=/\nL=/g' |
sed 's/OU=/\nOU=/g' | sed 's/O=/\nO: /g' | sed 's/CN=/\nCN: /g' | sed 's/^ *//' | sed 's/^ *//' |
sed '/^ST=/d' | sed '/^OU=/d' | sed '/^L=/d' | tr '[:space:]' ' ' | sed 's/Subject:/\nSubject:/g' |
sed 's/ O:/| O:/g' | sed 's/ CN:/| CN:/g' | sed 's/^ *//')
crt_shas=$(jq -r '.[] | {Subject: .dns_names[], Issuer: .issuer.name, Issued: .not_before, Expires: .not_after, CertSHA256: .cert.sha256}' $tempdir/certs.json |
tr -d '{",}' | sed 's/^ *//' | sed '/^$/d' | tr '[:space:]' ' ' | sed 's/Subject:/\nSubject:/g' | awk '{print $NF}' | sort -u)
for c in $crt_shas; do
echo -e "\n$c (CertSha-256)"
echo "$issuances" | grep -w "${c}" | awk -F'CertSHA256:' '{print $1}' | sed 's/Subject:/\n\nSubject:/g' | sed 's/Issuer:/\nIssuer:/g' |
sed 's/Issued:/\nIssued: /g' | sed 's/Expires:/\nExpires:/g' | sed '/Expires:/G'; done
echo "$dnsnames" | sed '/sni.cloudflaressl.com/d' | sort -u >> $tempdir/dnsnames; else
echo -e "\nNo results\n"; fi; else
echo -e "\nNo response\n"; fi
}
f_RUN_TESTSSL(){
local s="$*"
if [ -n "${PATH_testssl}" ]; then
if [ $option_testssl = "1" ] && [ $option_connect != "0" ]; then
${PATH_testssl} --quiet --color=0 --warnings batch --sneaky --phone-out --mapping no-iana -p -s -S -P -H -R -B -C $s |
sed 's/^[ \t]*//;s/[ \t]*$//' | grep -Ev "^Done|^DNS CAA" > $tempdir/testtls
grep -E "^Start|offered|^Hexcode|\(server order\)|^x|^Has server cipher|^SSL Session ID|^Session Resumption|^TLS clock|^Certificate Compression|^Client Authentication|^Common Name|^Trust|^Chain of|^EV cert|^ETS|^In pwnedkeys\.com|Revocation List|OCSP|Certificate Transparency|Certificates provided|^Intermediate|<--|^Heartbleed |^Secure|^CRIME|^BREACH" $tempdir/testtls |
sed '/Start/i \\n_______________________________________________________________________________\n\n'  |
sed 's/^.*\(-->>.*\).*$/\1/g' | sed '/Has server cipher/{x;p;x}' | sed 's/^SSLv2/\n\nSSLv2/g' | sed '/^SSLv3/G' |
sed '/Export ciphers/{x;p;x}' | sed '/Strong encryption/{x;p;x}' | sed '/(server order)/{x;p;x;G}' |
sed '/NULL ciphers /i \\n___________________________________________________________________\n\n' | sed 's/-->>//g' |
sed '/SSL Session ID support /i \\n___________________________________________________________________\n\n' | 
sed '/Common Name (CN)/i\\n___________________________________________________________________\n' | sed 's/<<--//g' |
sed '/Trust (hostname)/i \___________________________________________________________________\n\n' | sed '/SPDY/{x;p;x;}' |
sed '/^Certificates provided/a \\n___________________________________________________________________\n' | 
sed '/Hexcode/i \\n\n----------------------------------------------------------------------' |
sed '/Hexcode/a \----------------------------------------------------------------------' |
sed '/Heartbleed/i \___________________________________________________________________\n\n' | sed '/Chain of/G' |
sed '/Revocation List/G' | sed '/must staple/G' | sed 's/Intermediate cert validity/Intermediate cert validity\n\n/g' |
sed '/Intermediate Bad/{x;p;x;}' | sed '/BREACH/{x;p;x}' | sed 's/(CVE-2013-3587)/(CVE-2013-3587)\n/' |
sed 's/^[ \t]*//;s/[ \t]*$//'; echo ''; fi; else
echo -e "\ntestssl.sh: No executable found\n"; fi
}
f_SRV_CERT(){
echo -e "\nCertificate SHA256:\n"
dst_ip=$(grep 'IP:' $tempdir/curlw | grep -sEo "$REGEX_IP46" | tr -d ' ')
srv_name=$(grep 'URL' $tempdir/curlw | cut -d ':' -f 2- | sed 's/http:\/\///' | sed 's/https:\/\///' | cut -d '/' -f 1 | tr -d ' ')
echo | timeout 10 openssl s_client -connect [$dst_ip]:443 -servername $srv_name -verify_hostname $x -brief 2>$tempdir/srv_ssl1
ssl_error=$(grep 'error:num=' $tempdir/srv_ssl1 | grep -sEo "[0-9]{1,3}")
if [ -n "$ssl_error" ]; then
echo ''; grep 'error:num' $tempdir/srv_ssl1
echo -e "\nVerification attempted for server name $srv_name and hostname $x\n"; else
echo | timeout 3 openssl s_client -connect [$1]:443 -servername $srv_name 2>/dev/null | openssl x509 -noout -nocert -nameopt multiline -subject -issuer -dates -fingerprint -sha256 > $tempdir/srv_ssl2
cert_sha=$(grep 'SHA256' $tempdir/srv_ssl2 | tail -1 | cut -s -d '=' -f 2 | tr -d ':' | tr -d ' ')
protocol=$(grep -E "^Protocol version:" $tempdir/srv_ssl1 | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
expires=$(grep 'notAfter=' $tempdir/srv_ssl2 | cut -d '=' -f 2- | awk '{print $1,$2,$4}')
srv_verify=$(grep -sEa "^Verification" $tempdir/srv_ssl1 | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
host_verify=$(grep -sE "^Verified peername:" $tempdir/srv_ssl1 | awk '{print $NF}' | tr -d ' ')
peer_cn=$(grep 'CN =' $tempdir/srv_ssl1 | awk -F 'CN =' '{print $2}' | awk '{print $1}')
echo -e "$cert_sha\n"
echo -e "$protocol  |  $srv_verify  ($host_verify)  |  Exp: $expires  |  CN: $peer_cn\n"; fi
}
f_handshakeHEADER(){
local s="$*"; f_HEADLINE "$s  SSL HANDSHAKE  |  $(date -R)"; cat $tempdir/pubip
if [[ $(sort -u $tempdir/ips_all | wc -w) -gt 1 ]]; then
f_HEADLINE2 "TARGET DNS\n"
f_printADDR "$(dig @9.9.9.9 +short $s | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sort -u)"
f_printADDR "$(dig @9.9.9.9 aaaa +short $s | grep ':' | sort -u)"; else
echo ''; fi
}
f_printHANDSHAKE(){
f_HEADLINE2 "$1\n" >> $tempdir/hndshake; grep -v 'Endpoint:' $tempdir/curlw | sed G >> $tempdir/hndshake
f_SSL_HANDSHAKE "$tempdir/curl_verbose" >> $tempdir/hndshake
}
f_SSL_HANDSHAKE(){
local s="$*"; echo ''; f_Long; echo ''; sed '/^$/d' ${s} | sed 's/ = /=/' |
grep -E -i "HTTP/.*|HTTP1.*|HTTP2|Re-using|* Connection|TCP_NODELAY|ALPN|ID|SSL connection|SSL certificate|server:|Server certificate:|> GET|> HEAD|handshake|connected to|expire|squid|via:|location:|proxy|x-client-location:|x-varnish|accepted to use|CN=|date:|content-length:|SPDY|cache-control:|content-length" |
sed '/P3P:/d' | sed '/[Ff]eature-[Pp]olicy:/d' | sed '/[Pp]ermissions-[Pp]olicy:/d' |
sed '/Server [Cc]ertificate:/a \___________________________________\n' | sed '/[Cc]ontent-[Ss]ecurity-[Pp]olicy:/d' |
sed '/SSL connection using/i \\n---------------------------------------------------------------------\n' |
sed '/Connected to /a \________________________________________________________________________\n\n' |
sed '/Connected to /i \\n________________________________________________________________________\n' |
sed '/Server certificate:/{x;p;x;}' | sed -e :a -e 's/\(.*[0-9]\)\([0-9]\{4\}\)/\1/;ta' | sed '/[Cc]ontent-[Ll]anguage/d' |
sed '/SSL [Cc]ertificate verify/a \\n---------------------------------------------------------------------\n' | fmt -w 120 -s; echo -e "\n"
}

#-------------------------------  HTTP HEADERS  &  WEB SERVER / WEB SITE  INFO  -------------------------------

f_CURL_WRITEOUT(){
local s="$*"
curl -m 20 ${curl_array[@]} --trace-time ${curl_ua} $s 2>$tempdir/curl -D $tempdir/headers -o $tempdir/page_tmp -w \
"
Endpoint:     HTTP/%{http_version} %{response_code} | %{remote_ip} | tcp/%{remote_port} | Redirects: %{num_redirects}
Response:     HTTP/%{http_version} %{response_code} | Redirects: %{num_redirects} (%{time_redirect} s) | TOTAL:  %{time_total} s
IP:           %{remote_ip}  (tcp/%{remote_port})
URL:          %{url_effective}
" > $tempdir/response
grep -E ">|<|\*" $tempdir/curl | sed 's/*/   /' | sed 's/>/ > /' | sed 's/</ < /' > $tempdir/curl_verbose
sed 's/^[ \t]*//;s/[ \t]*$//' $tempdir/page_tmp | sed '/^$/d' | tr "'" '"' > $tempdir/page
sed 's/^[ \t]*//;s/[ \t]*$//' $tempdir/curl | cut -d ' ' -f 3- | sed 's/^ *//' > $tempdir/curl_trimmed
cat $tempdir/response > $tempdir/curlw; cat $tempdir/curl_trimmed > $tempdir/verb
f_EXTRACT_IP4 "$(grep -E "Connected to" $tempdir/curl_trimmed)" >> $tempdir/ip4.list
f_EXTRACT_IP6 "$(grep -E "Connected to" $tempdir/curl_trimmed)" >> $tempdir/ip6.list
cat $tempdir/headers | tr [:upper:] [:lower:] > $tempdir/h3; detect_cdn=$(f_detectCDN "$tempdir/h3")
}
f_getCMS(){
unset target_cms; unset cms_comment; unset meta_gen; unset powered_by; [[ -f $tempdir/cms ]] && rm $tempdir/cms
if [ -f $tempdir/ww ]; then
pow_by=$(sed 's/X-Powered-By//' $tempdir/ww | grep -soP 'Powered-By\[\K.*?(?=\])' | sort -bifu)
meta_gen=$(f_getWW_ITEM "MetaGenerator" | sort -bifu)
grep -sEaoi -m 1 "1024-CMS|bitrix|contao|drupal|joomla|librecms|liferay|pluck-cms|pragmamx|typo3|wordpress" $tempdir/ww > $tempdir/cms; fi
if  [ $option_connect != "0" ]; then
if [ -z "$meta_gen" ]; then
meta_gen=$(grep '<meta' $tempdir/no_space |  grep -sEi "name=(\")?generator" | grep -sioP 'content=\"\K.*?(?=\")' |
sed 's/^[ \t]*//;s/[ \t]*$//' | sort -bfiu | tr '[:space:]' ' '; echo ''); fi
if [ $ww = "false" ]; then
cms_comment="(enable source 'WhatWeb' to improve detection)"
if [ -f $tempdir/cms_src ]; then
grep -sEoi "api\.w\.org|typo3|liferay-portal|wp-admin|wp-content|wp-includes|wp-json|wordpress" $tempdir/cms_src |
tr [:upper:] [:lower:] | sed 's/api.w.org/wordpress/' | sed 's/wp-admin/wordpress/g' | sed 's/wp-content/wordpress/g' |
sed 's/wp-includes/wordpress/g' | sed 's/wp-json/wordpress/' | sed 's/liferay-portal/liferay/' |
sed 's/^[ \t]*//;s/[ \t]*$//' > $tempdir/cms; fi; fi; fi
if [ -f $tempdir/cms ]; then
target_cms=$(sed 's/^[ \t]*//;s/[ \t]*$//' $tempdir/cms | sort -fiuV | tail -1 | tr [:lower:] [:upper:] | sed 's/__/ /g' |
sed 's/CMS/ CMS/' | sed 's/TYPO3/TYPO3 /' | sed 's/TYPO3  CMS/TYPO3 CMS/'); fi
[[ -n "$target_cms" ]] && echo -e "CMS:          $target_cms $cms_comment\n" || echo -e "CMS:          none/unknown  $cms_comment\n"
if [ -n "$meta_gen" ]; then
echo -e "MetaGen:      $meta_gen"
echo -e "\n\n! Meta Generator:\n\n  Potential information disclosure vulnerability detected" >> $tempdir/dis_issues; fi
if [ -n "$powered_by" ]; then
echo -e "PoweredBy:    $powered_by"
echo -e "\n\n! Powered By:\n\n  Potential information disclosure vulnerability detected" >> $tempdir/dis_issues; fi
}
f_getDOCTYPE(){
if [ $option_connect = "0" ] && [ -f $tempdir/ww ]; then 
html_5=$(grep -sow -m 1 'HTML5' $tempdir/ww); [[ -n "$html_5" ]] && echo -e "HTML5:        true" || echo -e "HTML5:         false"; else 
doctype=$(grep -E -i "<\!doctype" $tempdir/page | grep -i -o -E "XHTML.[1-2]|HTML.[1-4]|<\!doctype html>" | tr [:lower:] [:upper:] |
sed 's/<!DOCTYPE HTML>/HTML5/'); [[ -n "$doctype" ]] && echo "Doctype:      $doctype"; fi
}
f_getHTTP_SERVER(){
if [ -f $tempdir/ww ]; then
server_redirs=$(f_getWW_ITEM "HTTPServer" | sort -bfiu | wc -l); else
server_redirs=$(grep -sEiw "^server:" $tempdir/headers | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | sort -bfiu | wc -l); fi
if [[ $server_redirs -gt 0 ]]; then
if [[ $server_redirs -gt 1 ]]; then
[[ -f $tempdir/ww ]] && server_header=$(grep -s -oP '(HTTPServer\[).*?(?=\,)' $tempdir/ww | sed 's/HTTPServer\[/=>/' | tr -d ']')
[[ -z "$server_header" ]] && [[ $option_connect != "0" ]] && server_header=$(grep -sEiw "^server:" $tempdir/headers | sed 's/[Ss]erver:/=>/g')
print_serv=$(f_printHEADER_ITEM "$server_header"); else
[[ -f $tempdir/ww ]] && print_serv=$(f_getWW_ITEM "HTTPServer" | tail -1) || print_serv=$(grep -sEiw "^server:" $tempdir/headers | tail -1 | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//'); fi; if [ -n "$print_serv" ]; then
echo -e "\nServer:       $print_serv"; server_vers=$(echo "$print_serv" | grep -Eoc "[0-9]")
server_os=$(echo "$print_serv" | grep -sEoic "Linux|Debian|Ubuntu|CentOS|buster|stretch|jessie|squeeze|wheezy|lenny|SUSE|Red Hat|Linux|Windows")
if [[ $server_os -gt 0 ]]; then
echo -e "\n\n! Server: \n\n  Information disclosure vulnerability detected - Server OS" >> $tempdir/dis_issues; else 
[[ $server_vers -gt 0 ]] && echo -e "\n\n! Server: \n\n  Potential information disclosure vulnerability detected" >> $tempdir/dis_issues; fi; fi; else 
echo -e "\nServer:       Unknown"; fi
}
f_getLANG(){
if [ -f $tempdir/ww ]; then
m_author=$(f_getWW_ITEM "Meta-Author"); contl=$(f_getWW_ITEM "Content-Language"); fi
if [ $option_connect != "0" ]; then
if [ -f $tempdir/metas ]; then
[[ -z "$m_author" ]] && m_author=$(grep -sEai "name=author|name=\"author" $tempdir/metas | grep -sioP 'content=\"\K.*?(?=\")')
[[ -z "$contl" ]] && contl=$(grep -sioP '(name=content-language).*?(?=>)' $tempdir/metas | awk -F'content=' '{print $2}' | sed 's/^ *//' | head -1); fi
[[ -z "$contl" ]] && contl=$(grep -i html $tempdir/page | tr -d '"' | tr -d "'" | grep -Eio -m 1 "lang=[a-z]{2,3}" | sed 's/lang=//' | head -1); fi
[[ -n "$contl" ]] && echo "Language:     $contl"; [[ -n "$m_author" ]] && echo "Author:       $m_author"
}
f_getMETA_TAGS(){
if [ -f $tempdir/metas ]; then
if [[ $(grep -sEiac "title|description|keywords|og:(url|title|description)" $tempdir/metas) -gt 0 ]]; then
page_title=$(f_getTITLE | awk -F'Title:' '{print $2}' | sed 's/^[ \t]*//;s/[ \t]*$//')
meta_title=$(grep -sEai "name=title|name=\"title" $tempdir/metas | grep -sioP 'content=\"\K.*?(?=\")')
meta_descr=$(grep -sEai "name=description|name=\"description" $tempdir/metas | grep -sioP 'content=\"\K.*?(?=\")')
meta_keyw=$(grep -sEai "name=keywords|name=\"keywords" $tempdir/metas | grep -sioP 'content=\"\K.*?(?=\")')
og_type=$(grep -sEai "property=og:type|property=\"og:type" $tempdir/metas | grep -sioP 'content=\"\K.*?(?=\")')
og_title=$(grep -sEai "property=og:title|property=\"og:title" $tempdir/metas | grep -sioP 'content=\"\K.*?(?=\")')
og_descr=$(grep -sEai "property=og:description|property=\"og:description" $tempdir/metas | grep -sioP 'content=\"\K.*?(?=\")')
og_url=$(grep -sEai "property=og:url|property=\"og:url" $tempdir/metas | grep -sioP 'content=\"\K.*?(?=\")')
f_HEADLINE2 "META TAGS"
[[ -n "$meta_descr" ]] && echo -e "\n\nDESCRIPTION\n" && echo -e "$meta_descr" | fmt -s -w 65
[[ -n "$meta_keyw" ]] && echo -e "\n\nKEYWORDS\n" && echo -e "$meta_keyw" | sed 's/,/, /g' | fmt -s -w 70
[[ -n "$print_title" ]] && echo -e "\n\nMETA TITLE\n\n$meta_title"
if [[ $(grep -sEic "og:" $tempdir/metas) -gt 0 ]]; then
echo -e "\n\nOPEN-GRAPH-PROTOCOL\n"
if [ -n "$og_title" ]; then
[[ "$og_title" = "$page_title" ]] && echo -e "Title:  Matches website title" || echo -e "Title:  $og_title"; fi
[[ -n "$og_url" ]] && echo -e "URL:    $og_url" || echo -e "URL:    No URL provided for $x"
if [ -n "$og_descr" ]; then
[[ "$og_descr" = "$meta_descr" ]] && echo -e "Descr:  Matches meta description" || echo -e "\nDescription:\n\n$og_descr"; fi; fi; fi; fi
}
f_getPAGE_INFO(){
unset redir; [[ -f $tempdir/ww ]] && rm $tempdir/ww; [[ -f $tempdir/response ]] && rm $tempdir/response
[[ $option_connect != "0" ]] && f_CURL_WRITEOUT "$x" && f_HEADERS "$x" > ${outdir}/HTTP_HEADERS.$x.txt
[[ $ww = "true" ]] && f_getWHATWEB; cat $tempdir/headers | tr [:upper:] [:lower:] > $tempdir/h3
detect_cdn=$(f_detectCDN "$tempdir/h3")
[[ $(grep -wioc 'Imperva_Incapsula' $tempdir/cdn) -gt 0 ]] && imperva="true" || imperva="false"
#***** checking for <meta> redirects (cURL doesn't parse html)
if [ -f $tempdir/ww ]; then
redir=$(grep -soP 'Meta-Refresh-Redirect\[\K.*?(?=\])' $tempdir/ww); else
if [ $option_connect != "0" ]; then
redir=$(grep -sEi "<meta http-equiv=(\")?refresh" $tempdir/page | awk -F'[Uu][Rr][Ll]=' '{print $NF}' | grep -oaEi "https?://[^\"\\'> ]+"); fi; fi
if [ -n "$redir" ]; then
target=$(echo "$redir" | sed 's/http:\/\///' | sed 's/https:\/\///' | cut -d '/' -f 1)
f_CURL_WRITEOUT "$target"; f_HEADERS "$target" >> ${outdir}/HTTP_HEADERS.$x.txt
[[ $ww = "true" ]] && f_getWHATWEB; cat $tempdir/headers | tr [:upper:] [:lower:] > $tempdir/h3
detect_cdn=$(f_detectCDN "$tempdir/h3")
[[ $(grep -wioc 'Imperva_Incapsula' $tempdir/cdn) -gt 0 ]] && imperva="true" || imperva="false"; else
target="$x"; fi; export target; target_url=$(grep -sE "^URL:" $tempdir/curlw_sum | awk '{print $NF}' | tr -d ' ')
if [ $imperva = "false" ]; then
f_getTXTS "$target"; cat $tempdir/page | tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/<title/\n\n<title/g' |
sed 's/<\/title>/<\/title>\n\n/g' | sed 's/<meta/\n\n<meta/g' | sed 's/<script/\n\n<script/g' > $tempdir/no_space
grep -sioP '(<script).*?(?=<\/script>)' $tempdir/no_space | tee $tempdir/cms_src > $tempdir/page_scripts
grep -sioP '(<meta).*?(?=>)'  $tempdir/no_space | tee -a $tempdir/cms_src > $tempdir/metas
grep -sioP '(src=").*?(?=")' $tempdir/page | awk -F'src=' '{print $2}' | tr -d '"' | tr -d ' ' | tee -a $tempdir/cms_src > $tempdir/site_src
sed 's/<link/\n\n<link/g' $tempdir/page | grep -A 1 '<link' | grep -sE "rel=\"(favicon|icon|shortcut|stylesheet)" |
grep -sioP '(href=").*?(?=")' | tee -a $tempdir/cms_src >> $tempdir/site_src; grep -sEai -v "^location:" $tempdir/headers >> $tempdir/cms_src
[[ -f $tempdir/robots.txt ]] && cat $tempdir/robots.txt >> $tempdir/cms_src
[[ -f $tempdir/humans.txt ]] && cat $tempdir/humans.txt >> $tempdir/cms_src; fi
[[ $report = "true" ]] && cat $tempdir/page_tmp > $outdir/SOURCE.${target}.html
}
f_getSCRIPTS(){
unset script_types; [[ -f $tempdir/jqu ]] && rm $tempdir/jqu; [[ -f $tempdir/php ]] && rm $tempdir/php;
[[ -f $tempdir/scripts ]] && rm $tempdir/scripts
if [ $option_connect != "0" ] && [ -f $tempdir/page_scripts ]; then
script_types=$(grep -sEoi "text/\b[A-Za-z0-9.+]{1,30}\b|application/\b[A-Za-z0-9.+]{1,30}\b" $tempdir/page_scripts | grep -sEi -v "text/(html|css)" |
sort -u)
grep -sEoi "jquery+[-_/\.]+[0-9x]+[-_/\.]+[0-9x](+[-_/\.]+[0-9x]+[-_/\.][0-9x]+[-_/\.][0-9x]+[-_/\.]+[0-9x])?\b" $tempdir/page_scripts |
sort -bifuV > $tempdir/jqu
grep -sEoi "PHP+[-_/\.]+[0-9x]+[-_/\.]+[0-9x]{1,2}(+[-_/\.]+[0-9x]{1,2})?+([-_/\.]+[0-9x]{1,2})?" $tempdir/headers | sort -bifuV > $tempdir/php
[[ -f $tempdir/php ]] || grep -sEoi "^x-generator:|^x-powered-by:|^set-cookie:|^server:" $tempdir/headers | grep -io -m 1 'php' >> $tempdir/php; fi
if [ -f $tempdir/ww ]; then
script_types=$(f_getWW_ITEM "Script" | sed 's/,/\n/g')
f_getWW_ITEM "JQuery" >> $tempdir/jqu; [[ -f $tempdir/jqu ]] || grep -sio -m 1 'jquery' $tempdir/ww >> $tempdir/jqu
f_getWW_ITEM "PHP" >> $tempdir/php; [[ -f $tempdir/php ]] || grep -sio -m 1 'php' $tempdir/ww >> $tempdir/php; fi
if [ -z "$script_types" ] || [[ $(f_countW "$script_types") -eq 0 ]]; then
if [ -f $tempdir/ww ]; then
grep -o -m 1 'Script' $tempdir/ww | sed 's/Script/Script\[unknown type\]/' > $tempdir/scripts; else
[[ -f $tempdir/page_scripts ]] && grep -io -m 1 '<script' $tempdir/page_scripts | tr -d '<' |  sed 's/script/Script\[unknown type\]/' > $tempdir/scripts; fi; else
echo "$script_types" | sort -u > $tempdir/scripts; fi
[[ -f $tempdir/jqu ]] && cat $tempdir/jqu >> $tempdir/scripts
[[ -f $tempdir/php ]] && f_toUPPER "$(sort -uV $tempdir/php | tail -1)" >> $tempdir/scripts
if [ -f $tempdir/scripts ]; then
scripts_raw=$(sed 's/jquery/JQuery/' $tempdir/scripts); print_scripts=$(f_printCSV "$scripts_raw")
[[ $(f_countW "$print_scripts") -lt 9 ]] && echo -e "Script:       $print_scripts" || echo -e "\nScript:\n\n$print_scripts\n"; fi 
}
f_getTITLE(){
local f="$*"; [[ -f $tempdir/ww ]] && title_raw=$(f_getWW_ITEM "Title" | tail -1)
[[ -z "$title_raw" ]] && [[ $option_connect != "0" ]] && title_raw=$(grep -sioP '<title>\K.*?(?=</title>)' $tempdir/no_space | head -1);
if [ -n "$title_raw" ]; then
title=$(echo "$title_raw" | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/&#8211;/-/g' | sed 's/\&amp;/\&/g' | sed "s/&#39;/\'/g" | sed 's/^ *//')
echo -e "\nTitle:        $title"; fi
}
f_getTXTS(){
local s="$*"
[[ -f $tempdir/humans ]] && rm $tempdir/humans
[[ -f $tempdir/security ]] && rm $tempdir/security
[[ -f $tempdir/robots ]] && rm $tempdir/robots
if [[ $(grep -w -i -o  "Incapsula" $tempdir/cdn | wc -w) = 0 ]]; then
status_humans=$(curl -sLk $s/humans.txt -o $tempdir/humans -w %{http_code})
if [ $status_humans = "200" ] ; then
cat $tempdir/humans > $tempdir/humans.txt; rm $tempdir/humans
if [[ $(grep -i -c "DOCTYPE" $tempdir/humans.txt) -gt 0 ]]; then
echo "humans.txt: false" >> $tempdir/server_files; else
if [[ $(wc -w < $tempdir/humans.txt) -lt 1 ]]; then
echo "| humans.txt: empty file" >> $tempdir/server_files; rm $tempdir/humans.txt; else
cat $tempdir/humans.txt >> $tempdir/cms; echo "humans.txt: true" >> $tempdir/server_files
f_HEADLINE "$s | humans.txt | $file_date" > ${outdir}/HUMANS.TXT.${s}.txt
cat $tempdir/humans.txt >> ${outdir}/HUMANS.TXT.${s}.txt; fi; fi
[[ $page_details = "false" ]] && rm $tempdir/humans.txt; else
echo "humans.txt: false" >> $tempdir/server_files; fi
status_security=$(curl -sLk $s/security.txt -o $tempdir/security -w %{http_code})
if [ $status_security = "200" ]; then
cat $tempdir/security > $tempdir/security.txt; rm $tempdir/security
if [[ $(grep -i -c "DOCTYPE" $tempdir/security.txt) -gt 0 ]]; then
echo "| security.txt: false" >> $tempdir/server_files; else
if [[ $(wc -w < $tempdir/security.txt) -lt 1 ]]; then
echo "| security.txt: empty file" >> $tempdir/server_files; rm $tempdir/security.txt; else
echo "| security.txt: true" >> $tempdir/server_files
f_HEADLINE "$s | security.txt | $file_date" > ${outdir}/SECURITY.TXT.${s}.txt
cat $tempdir/security.txt >> ${outdir}/SECURITY.TXT.${s}.txt; fi; fi
[[ $page_details = "false" ]] && rm $tempdir/security.txt; else
echo "| security.txt: false" >> $tempdir/server_files; fi
status_robots=$(curl -sLk $s/robots.txt -o $tempdir/robots -w %{http_code})
if [ $status_robots = "200" ]; then
cat $tempdir/robots > $tempdir/robots.txt; rm $tempdir/robots
if [[ $(grep -i -c "DOCTYPE" $tempdir/robots.txt) -gt 0 ]]; then
echo "| robots.txt: false" >> $tempdir/server_files; else
if [[ $(wc -w < $tempdir/robots.txt) -lt 1 ]]; then
echo "| robots.txt: empty file" >> $tempdir/server_files; rm $tempdir/robots.txt; else
cat $tempdir/robots.txt >> $tempdir/cms_src; echo "| robots.txt: true" >> $tempdir/server_files
f_HEADLINE "$s | robots.txt | $file_date" > ${outdir}/ROBOTS.TXT.${s}.txt
cat $tempdir/robots.txt >> ${outdir}/ROBOTS.TXT.${s}.txt; fi; fi
[[ $page_details = "false" ]] && rm $tempdir/robots.txt; else
echo "| robots.txt: false" >> $tempdir/server_files; fi; fi
}
f_getWEB_OTHER(){
unset google_ua; unset web_other
if [ -f $tempdir/ww ]; then
web_other=$(grep -sEoi "Adobe-Flash|AWStats|AzureCloud|Bootstrap|ColdFusion|Confluence|Fortiweb|Frame|highlight\.js|Lightbox|Modernizr|Incapsula-WAF|Open-Cart|Open-Graph-Protocol|OpenSearch|Shopify|Varnish|Vimeo|Youtube" $tempdir/ww | sed 's/^[ \t]*//;s/[ \t]*$//' | sort -bifu | tr '[:space:]' ' '; echo '')
cxnsc=$(f_getWW_ITEM "Citrix-NetScaler"); blb=$(f_getWW_ITEM "Barracuda-Load-Balancer"); bwaf=$(f_getWW_ITEM "Barracuda-Waf")
google_ua=$(f_getWW_ITEM "Google-Analytics" | grep -sEoi "UA-[0-9-]{3,11}")
[[ -n "$google_ua" ]] && echo "$google_ua" > $tempdir/web_tmp
[[ $option_connect = "0" ]] && [[ $(f_countW "$web_other") -gt 3 ]] && echo ''; fi 
if [ $option_connect != "0" ]; then
ganalytics=$(grep -sEo -m 1 "google-analytics.com|google_analytics.js|gtag\(" $tempdir/page_scripts)
if [ -z "$google_ua" ]; then
[[ -n "$ganalytics" ]] && google_ua=$(grep -sEoi -m 1 "UA-[0-9-]{3,11}" $tempdir/page_scripts) && echo "G_Analytics-ID: $google_ua" > $tempdir/web_tmp; fi
[[ -z "$google_ua" ]] && grep -so "\.googletagmanager\." $tempdir/page_scripts | sed 's/.googletagmanager./GoogleTagManager/' | tail -1 >> $tempdir/web_tmp
grep -sEo "fonts\.googleapis|fonts\.gstatic" $tempdir/site_src | grep -o 'fonts' | tail -1 | sed 's/fonts/GoogleFonts/' >> $tempdir/web_tmp; fi
[[ -n "$web_other" ]] && echo "$web_other" >>  $tempdir/web_tmp; [[ -n "$blb" ]] && echo "$blb" >> $tempdir/web_tmp
[[ -n "$bwaf" ]] && echo "$bwaf" >> $tempdir/web_tmp; [[ -n "$cxnsc" ]] && echo "$cxnsc" >> $tempdir/web_tmp
if [[ $(wc -w < $tempdir/web_tmp) -gt 0 ]]; then
print_other=$(sed 's/^[ \t]*//;s/[ \t]*$//' $tempdir/web_tmp | tr '[:space:]' ' '; echo '')
[[ $ww = "false" ]] && echo "Google:       $print_other" || echo "Other         $print_other"; fi
}
f_getWHATWEB(){
if [ $ww = "true" ]; then
if [ $ww_source = "1" ]; then
curl -s -m 30 "https://api.hackertarget.com/whatweb/?q=${x}${api_key_ht}" > $tempdir/ww_raw; else
if [ $ww_source = "2" ] && ! [ $option_connect = "0" ]; then
if [ -n "$PATH_whatweb" ]; then
${PATH_whatweb} --no-errors --color=never --user-agent Mozilla/5.0 $x > $tempdir/ww_raw; else
echo -e "\n${R}Application not found.${D}\n\nPlease install WhatWeb and/or set application path within the script source\n"; fi; fi; fi
[[ $(grep -soP '(IP\[).*?(?=\])' $tempdir/ww_raw | wc -l) -gt 0 ]] && cat $tempdir/ww_raw > $tempdir/ww; fi
}
f_getWW_ITEM(){
grep -soP "$1\[\K.*?(?=],)" $tempdir/ww | tr -d '[]' | sed 's/,/, /g'
}
f_HTML_COMMENTS(){
local s="$*"; comments=$(${PATH_nmap} -Pn -sT -p 80,443 --script http-comments-displayer ${s} 2>/dev/null |
grep -E "80/tcp|443/tcp|\||\|_" | tr -d '|_' | sed 's/^ *//' | sed 's/Line number:/ | Line:/g' | tr '[:space:]' ' ' |
sed 's/Comment:/\n/g' | sed 's/443\/tcp/\n443\/tcp`/' | sed 's/Path:/\n\nPath:/g' | sed '/\/tcp/{x;p;x;G;}' |
sed 's/http-comments-displayer:/\n\n/' | sed 's/^ *//' | sed 's/<\!--/    <\!--/g' | sed 's/\/\*/    \/\*/g')
if [ -n "$comments" ] ; then
echo '' ; f_Long ; echo "[+] $s | HTML Comments" ; f_Long ; echo "$comments" | fmt -s -w 100 ; echo '' ; fi
}
f_LINK_DUMP(){
[[ -f $tempdir/print_ld ]] && rm $tempdir/print_ld; if [ -f $tempdir/ldump_raw ]; then
sed '/javascript:void(0)/d' $tempdir/ldump_raw | sed '/[Vv]isible [Ll]inks:/d' | sed '/[Hh]idden [Ll]inks:/d' |
sed '/Sichtbare Links:/d' | sed '/Versteckte Links:/d' | sort -f -u  > $tempdir/ldump
hosts_unique=$(grep -sEi "http:|https:" $tempdir/ldump | sed 's/http:\/\///' | sed 's/https:\/\///' |
cut -d '/' -f 1 | sed 's/^[ \t]*//;s/[ \t]*$//' | tr -d ' ' | sort -ifu)
echo '' > $tempdir/print_ld; f_HEADLINE "$target | LINK DUMP | $file_date" >> $tempdir/print_ld
cat $tempdir/ldump | sed '/^$/d' >> $tempdir/print_ld; echo '' >> $tempdir/print_ld
if [ -n "$hosts_unique" ]; then
f_Long >> $tempdir/print_ld; echo '' >> $tempdir/print_ld
for u in $hosts_unique ; do
host_addr=$(dig @9.9.9.9 +short $u | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -6 | tr '[:space:]' ' ')
echo -e "$u \n     $host_addr\n"; done > $tempdir/links_resolved
cat $tempdir/links_resolved >> $tempdir/print_ld
egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/links_resolved |
sort -t . -k 1,1n -k 2,2n -k 3,3n -u > $tempdir/ldump_ips
f_whoisTABLE "$tempdir/ldump_ips"; echo '' > $tempdir/pwhois_table; f_Long >> $tempdir/pwhois_table
cat $tempdir/whois_table.txt | cut -d '|' -f -5 | sed '/^$/d' | sed '/NET NAME/G' >> $tempdir/pwhois_table
cat $tempdir/pwhois_table >> $tempdir/print_ld; rm $tempdir/pwhois_table; fi
[[ $report = "true" ]] && cat $tempdir/print_ld > ${outdir}/LINK_DUMP.$x.txt; fi
}
f_PAGE(){
if [ $option_connect = "0" ]; then
f_WHATWEB; else
detect_cdn=$(f_detectCDN "$tempdir/h3"); f_Long; echo -e "\n"
grep -sE "^Response:|^IP:|^URL:" $tempdir/response | sed G
[[ $(grep -wioc 'Imperva_Incapsula' $tempdir/cdn) -gt 0 ]] && imperva="true" || imperva="false"
if [ $imperva = "true" ]; then
echo -e "\nTARGET WEBSITE:\n\nImperva Incapsula CDN detected.\n\nAborting attemps to scrape website..."; else
target_url=$(grep -sE "^URL:" $tempdir/response | awk '{print $NF}' | tr -d ' ')
target_ip=$(grep -sE "^IP:" $tempdir/response | grep -sEo "$REGEX_IP46"); proxy_headrs=$(f_getPROXY_HEADERS "$tempdir/headers")
if [ -n "$PATH_lynx" ]; then
timeout 10 ${PATH_lynx} -accept_all_cookies -crawl -dump -nonumbers $x > $tempdir/pages_text
timeout 10 ${PATH_lynx} -accept_all_cookies -dump -listonly -nonumbers $x > $tempdir/ldump_raw
timeout 10 ${PATH_lynx} -accept_all_cookies -crawl -dump -nonumbers $target_url >> $tempdir/pages_text
timeout 10 ${PATH_lynx} -accept_all_cookies -dump -listonly -nonumbers $target_url >> $tempdir/ldump_raw; fi
f_LINK_DUMP "$x"; proxy_headrs=$(f_getPROXY_HEADERS "$tempdir/headers"); scripts=$(f_getSCRIPTS); web_other=$(f_getWEB_OTHER)
rss_feed=$(grep -i 'application\/rss\+xml' $tempdir/page | grep -E -o "href=*.*>" | head -1 | cut -d '=' -f 2 | tr -d '>' |
tr -d '\"' | sed 's/^[ \t]*//;s/[ \t]*$//' | tr -d ' ')
if [ -f $tempdir/pages_text ]; then
iframes=$(grep 'IFRAME:' $tempdir/pages_text | sort -u | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' |
tr '[:space:]' ' '; echo ''); fi
f_getTITLE "$tempdir/page"; f_getHTTP_SERVER; [[ -n "$proxy_headrs" ]] && echo "Proxy:        $proxy_headrs"; f_getCMS
[[ -n "$scripts" ]] && echo "$scripts"; f_getLANG; f_getAPP_HEADERS "$tempdir/headers"
if [ -f $tempdir/ww ]; then
grep -soP '(PasswordField\[).*?(?=\])' $tempdir/ww | sed 's/PasswordField\[/PasswdField:  /' | tr -d ']'
grep -soP '(WWW-Authenticate\[).*?(?=\])' $tempdir/ww | sort -u | sed 's/WWW-Authenticate\[/WWW-Auth.:      /' | tr -d ']['; fi
[[ -n "$web_other" ]] && echo "$web_other"; [[ $(echo "$iframes" | wc -w) -gt 0 ]] && echo "Frame:        $iframes"
server_files=$(cat $tempdir/server_files | tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/^\|//' | sed 's/^ *//')
echo -e "\nTXTs:         $server_files\n"; rm $tempdir/server_files; f_getCOOKIES; fi
if [[ $(sort -u $tempdir/ips_all | wc -w) = 1 ]]; then
echo -e "\n________________________________________\n"
[[ $imperva = "false" ]] && echo -e "Website SHA1:\n\n$(sha1sum $tempdir/page_tmp | awk '{print $1}')"
f_SRV_CERT "$target_ip"; [[ $send_ping = "true" ]] &&  echo '' && f_Long && f_PING "$target_ip"; fi
f_getSEC_HEADERS "$tempdir/h3"; [[ -f $tempdir/dis_issues ]] && cat  $tempdir/dis_issues > $tempdir/issues
[[ -f $tempdir/h_issues ]] && cat $tempdir/h_issues >>  $tempdir/issues
if [ -f $tempdir/issues ]; then
[[ $(grep -sEoc "Meta-Generator:" $tempdir/issues) -gt 0 ]] && f_HEADLINE2 "SECURITY ISSUES  (HEADERS /<META>)" || f_HEADLINE2 "SECURITY ISSUES  (HEADERS)"
cat $tempdir/issues; echo ''; fi 
if [[ $imperva = "false" ]] && [[ $page_details = "true" ]]; then
f_getMETA_TAGS; f_SOCIAL "$x"
if [ -f $tempdir/humans.txt ]; then
[[ $(wc -l < $tempdir/humans.txt) -lt 41 ]] && f_HEADLINE2 "HUMANS.TXT\n" && cat $tempdir/humans.txt && echo ''
rm $tempdir/humans.txt; fi
if [ -f $tempdir/robots.txt ]; then
[[ $(wc -l < $tempdir/robots.txt) -lt 41 ]] && f_HEADLINE2 "ROBOTS.TXT\n" && cat $tempdir/robots.txt && echo ''
rm $tempdir/robots.txt; fi
if [ -f $tempdir/security.txt ]; then
[[ $(wc -l < $tempdir/security.txt) -lt 41 ]] && f_HEADLINE2 "SECURITY.TXT\n" && cat $tempdir/security.txt && echo ''
rm $tempdir/security.txt; fi; fi; fi
}
f_SERVER_INSTANCE(){
local srvip="$*"
[[ -f $tempdir/p2 ]] && rm $tempdir/p2; [[ -f $tempdir/writeout ]] && rm $tempdir/writeout; [[ -f $tempdir/h2 ]] && rm $tempdir/h2
[[ -f $tempdir/verbose ]] && rm $tempdir/verbose ]]
curl -m 15 $target_host ${st_array[@]} ${ua} --resolve "$target:$srvip" --trace-time 2>$tempdir/verbose -o $tempdir/p2 -D $tempdir/h2 -w \
"
Response:     HTTP/%{http_version} %{response_code} (tcp/%{remote_port}) | Redirects: %{num_redirects} (%{time_redirect} s) | TOTAL: %{time_total} s
IP:           %{remote_ip}
URL:          %{url_effective}
" > $tempdir/writeout; cat $tempdir/writeout > $tempdir/curlw
sed 's/^[ \t]*//;s/[ \t]*$//' $tempdir/verbose | cut -d ' ' -f 3- | sed 's/^ *//' > $tempdir/verb
cut -d ' ' -f 3- $tempdir/verbose | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' | sed 's/server:/Server:/g' | sed 's/via:/Via:/g' |
grep -E ">|<|\*" $tempdir/verbose | sed 's/*/   /' | sed 's/>/ > /' | sed 's/</ < /' >  $tempdir/curl_verbose
rem_ip=$(grep 'IP:' $tempdir/writeout | grep -sEo "$REGEX_IP46" | tr -d ' ')
cat $tempdir/headers | tr [:upper:] [:lower:] > $tempdir/h4; detect_cdn=$(f_detectCDN "$tempdir/h4")
[[ $(grep -wioc 'Imperva_Incapsula' $tempdir/cdn) -gt 0 ]] && imperva="true" || imperva="false"
[[ $rem_ip = $srvip ]] && f_HEADLINE2 "SERVER        $srvip\n" || f_HEADLINE2 "SERVER        $rem_ip   (REQUESTED:  $1)\n"
echo ''; grep -E "^Response:|^URL:" $tempdir/curlw | sed G
server_ips=$(grep -E "Connected to" $tempdir/verb | awk '{print ">"$4}' | tr -d '()' | sed 's/^[ \t]*//;s/[ \t]*$//' | tr -d ' ')
print_ips=$(echo "$server_ips" | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' | tr -d ' ' | sed 's/>/> /g' |
sed 's/^ *//' | sed 's/^\>//' | sed 's/>/ >/g')
[[ -n "print_ips" ]] && echo -e "IP:         $print_ips\n"
[[ "$rem_ip" != "$srvip" ]] && f_EXTRACT_IP4 "$rem_ip" >> $tempdir/ips_other && f_EXTRACT_IP6 "$rem_ip" >> $tempdir/ips_other6
echo -e "\n________________________________________\n"
[[ $imperva = "false" ]] && echo -e "Website SHA1:\n\n$(sha1sum $tempdir/p2 | awk '{print $1}')"
f_SRV_CERT "$rem_ip"; f_getSEC_HEADERS "$tempdir/h4"
}
f_SOCIAL(){
local s="$*"
[[ -f $tempdir/mail ]] && rm $tempdir/mail; [[ -f $tempdir/phone ]] && rm $tempdir/phone
[[ -f $tempdir/ww ]] && f_getEMAIL "$(grep -s -oP '(Email\[).*?(?=])' $tempdir/ww)" >> $tempdir/mail
for site in $subpages; do
curl -sLk ${curl_ua} ${s}/${site}; done > $tempdir/pages
cat $tempdir/page >> $tempdir/pages; cat $tempdir/ldump_raw >> $tempdir/pages
cat $tempdir/pages >> $tempdir/pages2; cat $tempdir/pages_text >> $tempdir/pages2
grep -sEo "\b[A-Za-z0-9._%+-]+(@|-at-|\(at\)|_AT_)[A-Za-z0-9.-]+(_DOT_|-dot-|\.)[A-Za-z]{2,6}\b" $tempdir/pages2 >> $tempdir/mail
grep -sEi -C 2 "phon.*|*.contact.*|*.telef.*|tel:|fon:|mobil.*|cell.*|contact.*|kontakt.*|.*support.*|.*customer.*" $tempdir/pages2 |
grep -sEo "\+[0-9]{2,6}[ -][0-9]{2,4}[ -]([0-9]{2,8}|[0-9]{2,4}[ -][0-9]{2,8})" > $tempdir/phone
grep -sEai "contact|kontakt|support|career|karriere" $tempdir/ldump > $tempdir/social_tmp
grep -E "^http.*" $tempdir/ldump > $tempdir/ldump_urls; grep -A 1 '<link' $tempdir/pages | grep -sE "rel=\"(publisher|me)" |
grep -soP 'href="\K.*?(?=")' | grep -E "^http.*" >> $tempdir/ldump_urls
[[ $x =~ "codepen" ]] || grep -sEai "codepen" $tempdir/ldump_urls >> $tempdir/social_tmp
[[ $x =~ "discord" ]] || grep -sEai "discord" $tempdir/ldump_urls >> $tempdir/social_tmp
[[ $x =~ "github" ]] || grep -sEai "github" $tempdir/ldump_urls >> $tempdir/social_tmp
[[ $x =~ "facebook" ]] || grep -sEai "facebook" $tempdir/ldump_urls >> $tempdir/social_tmp
[[ $x =~ "instagram" ]] || grep -sEai "instagram" $tempdir/ldump_urls >> $tempdir/social_tmp
[[ $x =~ "linkedin" ]] || grep -sEai "linkedin" $tempdir/ldump_urls >> $tempdir/social_tmp
[[ $x =~ "mastodon" ]] || grep -sEai "mastodon" $tempdir/ldump_urls >> $tempdir/social_tmp
[[ $x =~ "pinterest" ]] || grep -sEai "pinterest" $tempdir/ldump_urls >> $tempdir/social_tmp
[[ $x =~ "telegram" ]] || grep -sEai "telegram" $tempdir/ldump_urls >> $tempdir/social_tmp
[[ $x =~ "threma" ]] || grep -sEai "threma" $tempdir/ldump_urls >> $tempdir/social_tmp
[[ $x =~ "twitter" ]] || grep -sEai "twitter" $tempdir/ldump_urls >> $tempdir/social_tmp
[[ $x =~ "vk.ru" ]] || grep -sEai "vk.ru" $tempdir/ldump_urls >> $tempdir/social_tmp
[[ $x =~ "xing" ]] || grep -sEai "xing" $tempdir/ldump_urls >> $tempdir/social_tmp
[[ $x =~ "youtube" ]] || grep -sEai "youtube" $tempdir/ldump_urls >> $tempdir/social_tmp
social_links=$(sort -bifu $tempdir/social_tmp)
gmaps=$(grep -sai 'google' $tempdir/linkdump_urls | grep -sai 'maps' | grep -saiv 'api')
page_mail=$(sort -bifu $tempdir/mail | grep -E -v "\.jpg|\.png|\.gif|\.tiff|\.ico")
f_HEADLINE2 "SOCIAL MEDIA & CONTACTS\n\n"
[[ -n "$social_links" ]] && echo -e "$social_links\n"; [[ -n "$gmaps" ]] && echo -e "$gmaps\n"
[[ -f $tempdir/phone ]] && [[ $(wc -w  < $tempdir/phone) -gt 0 ]] && sort -uV $tempdir/phone && echo ''
[[ -n "$page_mail" ]] && echo "$page_mail"
}
f_WHATWEB(){
if [ -f $tempdir/ww ]; then
[[ -f $tempdir/sec_headers ]] && rm $tempdir/sec_headers; get_ips=$(f_getWW_ITEM "IP" | sort -u)
site_title=$(f_getTITLE "$tempdir/page"); ww_email=$(f_getEMAIL "$(grep -s -oP '(Email\[).*?(?=])' $tempdir/ww)")
[[ -n "$ww_email" ]] && print_mail=$(echo "$ww_email" | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//'; echo '')
proxy_headrs=$(f_getPROXY_HEADERS); get_cookies=$(f_getCOOKIES); ww_other=$(f_getWEB_OTHER)
uncommon=$(f_getWW_ITEM "UncommonHeaders" | sort -u | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//'; echo '')
grep -s -oP '(Strict-Transport-Security\[).*?(?=\])' $tempdir/ww | tail -1 | sed 's/\[/: /' | tr -d '][' > $tempdir/sec_headers
grep -s -oP '(X-Frame-Options\[).*?(?=\])' $tempdir/ww | tail -1 | sed 's/\[/:  /' | tr -d ']['  >> $tempdir/sec_headers
grep -s -oP '(X-XSS-Protection\[).*?(?=\])' $tempdir/ww | tail -1 | sed 's/\[/:  /' | tr -d ']['  >> $tempdir/sec_headers
grep -s -oP '(X-UA-Compatible\[).*?(?=\])' $tempdir/ww | tail -1 | sed 's/\[/:  /' | tr -d ']['  >> $tempdir/sec_headers
if [[ $(f_countW "$get_ips") -gt 1 ]]; then
print_srv_ips=$(grep -soP '(IP\[).*?(?=\])' $tempdir/ww | sed 's/IP\[/> /g' | tr '[:space:]' ' ' | sed 's/^ *//'); else
print_srv_ips="$get_ips"; fi; [[ $domain_enum = "false" ]] && f_HEADLINE2 "WHATWEB\n\n" || echo ''
awk -F ']' '{print $1}' $tempdir/ww | sed 's/\[/ /g' | sed '/^$/d' | sed G; echo -e "$print_srv_ips\n"
grep -sioP '(Meta-Refresh-Redirect\[).*?(?=])' $tempdir/ww | sed 's/Meta-Refresh-Redirect\[/\nMeta-Refresh:  Redirect to  ->  /'; echo ''
[[ -n "$site_title" ]] && echo -e "$site_title\n"; f_getHTTP_SERVER; [[ -n "$proxy_headrs" ]] && echo "Proxy:        $proxy_headrs"
f_getCMS; f_getDOCTYPE; f_getDOCTYPE; f_getSCRIPTS: f_getAPP_HEADERS; f_getLANG
grep -soP '(PasswordField\[).*?(?=\])' $tempdir/ww | sed 's/PasswordField\[/PasswdField:  /' | tr -d ']'
grep -soP '(WWW-Authenticate\[).*?(?=\])' $tempdir/ww | sort -u | sed 's/WWW-Authenticate\[/WWW-Auth.:      /' | tr -d ']['
[[ -n "$web_other" ]] && echo "$ww_other"
[[ -n "$ww_email" ]] && [[ $(f_countW "$ww_email") -lt 3 ]] && echo -e "\nEmail:   $print_mail" || echo -e "\n\nEMAIL\n" echo "$print_email" | fmt -w 70
[[ -f $tempdir/sec_headers ]] || [[ -n "$uncommon" ]] && echo -e "\n\nUNCOMMON & SECURITY HEADERS\n\n" || echo ''
[[ -f $tempdir/sec_headers ]] && cat $tempdir/sec_headers && echo ''; [[ -n "$uncommon" ]] && echo -e "$uncommon\n"
[[ -n "$get_cookies" ]] && echo -e "\nCOOKIES\n\n$get_cookies\n"; else
echo -e "\nWhatWeb (hackertarget.com IP tools)  -  Error retrieving results for $x"; fi 
}
f_wwwHEADER(){
echo ''; [[ $option_www = "1" ]] && headline="WEB SERVER HEALTH CHECK"
[[ $option_www = "2" ]] && headline="WEB SITE INFO"; [[ $option_www = "3" ]] && headline="HTTP HEADERS"
f_HEADLINE "$headline | $(date -R)"; f_CLIENT_INFO | tee $tempdir/pubip; echo -e "\nTarget:   $x\n"
}
#********************** WEB SERVERS/-SITES - URLSCAN **********************
f_getURLSCAN(){
local s="$*"
[[ -f $tempdir/urlscan.json ]] && rm $tempdir/urlscan.json; [[ -f $tempdir/urlscan ]] && rm $tempdir/urlscan
curl -s -m 7  "https://urlscan.io/api/v1/search/?q=domain:${s}" > $tempdir/urlscan.json
if [ -f $tempdir/urlscan.json ]; then
jq -r '.results[] | {URL: .task.url, IP: .page.ip, GEO: .page.country, HOST: .page.domain, STATUS: .page.status, SRV: .page.server, DOM: .page.apexDomain, TITLE: .page.title, ASN: .page.asn, ASNAME: .page.asnname, ISSUED: .page.tlsValidFrom, ValidDays: .page.tlsValidDays, Issuer: .page.tlsIssuer, SCR: .screenshot, DATE: .task.time}' $tempdir/urlscan.json | tr -d '{",}' | sed 's/^[ \t]*//;s/[ \t]*$//' | grep -v 'null' |
sed -e '/./{H;$!d;}' -e 'x;/IP:/!d;' | sed '/GEO:/a )' | sed '/^TITLE:/i |' | tr '[:space:]' ' ' | sed 's/URL:/\n\nURL:/g' |
sed 's/^[ \t]*//;s/[ \t]*$//' > $tempdir/urlscan; fi
}
f_printURLSCAN(){
local i="$*"; if [ -f $tempdir/urlscan ]; then
echo ''; grep -saw ${i} $tempdir/urlscan | sed 's/URL:/\n\n*/g' | sed 's/IP:/\n\n>/g' | sed 's/^ *//' | sed 's/GEO:/(/g' |
sed 's/( /(/g' | sed 's/HOST://g' | sed 's/STATUS:/\n\n  Status:/g' | sed 's/SRV:/| Server:/g' | sed 's/DOM:/| Domain:/g' |
sed 's/ )/)/g' | sed 's/| TITLE:/\n\n  Title: /g' | sed 's/ASN:/\n\n  ASN:   /g' | sed 's/ASNAME:/-/g' |
sed 's/ISSUED:/\n\n  Cert:   Issued:/g' | sed 's/DATE:/\n\n  Date:  /' | sed 's/ValidDays:/| Valid(days):/g' |
sed 's/Issuer:/| CA:/g' | sed 's/SCR:/\n\n  SCR:   /g' | sed '/./,$!d'; fi
}
f_urlSCAN_FULL(){
local s="$*"
if [ -f $tempdir/urlscan ]; then
f_HEADLINE "$s urlscan.io | $file_date"; v6=$(cat $tempdir/ip6.list | sort -uV)
v4=$(cat $tempdir/ip4.list | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n -u)
echo -e "$s\n"; [[ -n "$v4" ]] && f_printADDR "$v4"; [[ -n "$v6" ]] && f_printADDR "$v6"; f_Long; echo ''
cat $tempdir/urlscan | sed 's/URL:/\n\n*/g' | sed 's/IP:/\n\n>/g' | sed 's/^ *//' | sed 's/GEO:/(/g' | sed 's/( /(/g' |
sed 's/HOST://g' | sed 's/STATUS:/\n\n  Status:/g' | sed 's/SRV:/| Server:/g' | sed 's/DOM:/| Domain:/g' | sed 's/ )/)/g' |
sed 's/| TITLE:/\n\n  Title: /g' | sed 's/ASN:/\n\n  ASN:   /g' | sed 's/ASNAME:/-/g' |
sed 's/ISSUED:/\n\n  Cert:   Issued:/g' | sed 's/DATE:/\n\n  Date:  /' |
sed 's/ValidDays:/| Valid(days):/g' | sed 's/Issuer:/| CA:/g' | sed 's/SCR:/\n\n  SCR:   /g' | sed '/./,$!d'
egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/urlscan |
sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n -u > $tempdir/urlscan_ips
if [ -f $tempdir/urlscan_ips ]; then
f_whoisTABLE "$tempdir/urlscan_ips"; echo -e "\n"; f_Long
cat $tempdir/whois_table.txt | cut -d '|' -f -5 | sed '/^$/d' | sed '/NET NAME/{x;p;x;G}'; echo -e "\n"; fi; fi
}
#**********************  HTTP HEADERS  **********************
f_detectCDN(){
local hf="$*"; unset cdn
grep -sEi -v "^location:|^link:|^content-security-policy:|^cross-origin-resource-policy:|^x-permitted-cross-domain-policies:|^content-security-policy-report-only:"     ${hf} > $tempdir/h5
if [ -f $tempdir/h5 ]; then
if [[ $(grep -sEioc "cf-ray|cloudflare|cf-cache*" $tempdir/h5) -gt 0 ]]; then
cdn="Cloudflare"
elif [[ $(grep -sEioc "^fastly-.*|x-fastly.-*" $tempdir/h5) -gt 0 ]]; then
cdn="Fastly"
elif [[ $(grep -sEioc "incap_ses|incapsula|^x-original-uri:|^x-i*nfo:" $tempdir/h5) -gt 0 ]]; then
cdn="Imperva_Incapsula"
elif [[ $(grep -sEioc "originshieldhit|cloudfront-.*|x-amz-cf-id" $tempdir/h5) -gt 0 ]]; then
cdn="Amazon_AWS_CloudFront"; fi; fi
[[ -n "$cdn" ]] && echo -e "\nCDN:          $cdn" && echo "CDN: $cdn" > $tempdir/cdn || echo "CDN:  none/unknown" > $tempdir/cdn
}
f_getAPP_HEADERS(){
[[ -f $tempdir/app_headers ]] && rm $tempdir/app_headers
if [ -f $tempdir/ww ]; then
grep -soP 'X-Powered-By\[\K.*?(?=\])' $tempdir/ww >> $tempdir/app_headers
grep -soP 'X-Generator\[\K.*?(?=\])' $tempdir/ww >> $tempdir/app_headers; fi
if [ $option_connect != "0" ]; then
grep -sEiw "^x-aspnet-version:|^x-aspnetmvc-version:|^x-generator:|^x-powered-by:" $tempdir/headers |
cut -s -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' >> $tempdir/app_headers; fi
if [ -f $tempdir/app_headers ]; then
app_headers=$(sort -bfiu $tempdir/app_headers | sed 's/^/,/' | tr '[:space:]' ' ' | sed 's/^\,//' | sed 's/ ,/,/g' |
sed 's/,/, /g'; echo ''); if [ $(echo "$app_headers" | wc -w) -gt 0 ]; then
echo "AppHeaders:   $app_headers"; app_header_version=$(echo "$app_headers" | grep -sEoic "version|PHP")
[[ -n "$app_headers" ]] && echo -e "\n\n! Application Headers (e.g. x-powered-by, x-aspnet*):\n\n  Potential information disclosure vulnerability" >> $tempdir/dis_issues;
fi; fi
}
f_getCOOKIES(){
local s="$*"; if [ -f $tempdir/ww ]; then
unset cookies; unset cookie_count; unset http_only
cookies_raw=$(f_getWW_ITEM "Cookies" | sed 's/,/\n/g' | sed 's/^ *//' | sort -bifu)
cookie_count=$(f_countW "$cookies_raw"); if [[ $cookie_count -gt 0 ]]; then
cookies=$(f_printCSV "$cookies_raw"); htonly_raw=$(f_getWW_ITEM "HttpOnly" | sed 's/,/\n/g' | sed 's/^ *//' | sort -bifu)
htonly=$(f_printCSV "$htonly_raw"); echo -e "\nCookies:      $cookies"
[[ -n "$htonly" ]] && echo -e "\nHttpOnly:     $htonly" || echo -e "\nHttpOnly:     HttpOnly flag not set!"; fi; fi
}
f_getHEADERS(){
local s="$*"
if [ $header_source = "2" ] || [ $option_connect = "0" ] ; then
curl -s -m 5 "https://api.hackertarget.com/httpheaders/?q=${s}${api_key_ht}" > $tempdir/headers; else
curl -sILk -m 10 ${ua} ${s} > $tempdir/headers; fi
}
f_getPROXY_HEADERS(){
local s="$*"; if [ -f $tempdir/ww ]; then
f_getWW_ITEM "Via" | tail -1; f_getWW_ITEM "Via-Proxy" | tail -1; f_getWW_ITEM "X-Squid" | tail -1
f_getWW_ITEM "X-Varnish" | tail -1; else
[[ $option_connect != "0" ]] && grep -Eai "^Via:|^via-proxy:|^X-Squid|^X-Varnish:" $tempdir/headers; fi
[[ $option_connect != "0" ]] && grep -Eai "^X-Cache|^X-Server-Name:|^X-Server-Port:|^x-forwarded|^Forwarded|^proxy-auth:|x-pass-why:|x-redirect-by:" $tempdir/headers
}
f_getSEC_HEADERS(){
local s="$*"; unset rpol_objects; unset report_objects; f_HEADLINE2 "SECURITY HEADERS\n"
[[ -f $tempdir/deprecated ]] && rm $tempdir/deprecated; [[ -f $tempdir/headers_other ]] && rm $tempdir/headers_other
c_pol=$(grep -sEow "^content-security-policy:" ${s}); c_pol_report=$(grep -sEow "^content-security-policy-report-only:" ${s})
if [ -n "$c_pol" ]; then
cpol_objects=$(grep -sEi "^content-security-policy:" ${s} | grep -sEaio "base-uri|block-all-mixed-content|connect-src|default-src|font-src|form-action|frame-ancestors|frame-src|img-src|manifest-src|media-src|object-src|plugin-types|reflected-xss|report-uri|sandbox|script-nonce|script-src" | sort -u | 
tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//'; echo ''); fi
if [ -n "$c_pol_report" ]; then
report_objects=$(grep -sEi "^content-security-policy-report-only:" ${s} | grep -sEaio "base-uri|block-all-mixed-content|connect-src|default-src|font-src|form-action|frame-ancestors|frame-src|img-src|manifest-src|media-src|object-src|plugin-types|reflected-xss|report-uri|sandbox|script-nonce|script-src" | sort -u |
tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//'; echo ''); fi
c_control=$(f_printHEADER_ITEM "$(grep -sEw "^cache-control:" ${s} | sed 's/cache-control:/=>/')")
strict_ts=$(f_printHEADER_ITEM "$(grep -sEa "^strict-transport-security:" ${s} | sed 's/strict-transport-security:/=>/g')")
www_auth=$(f_printHEADER_ITEM "$(grep -sEw "^www-authenticate:" ${s} | sed 's/www-authenticate:/=>/g')")
x_frame=$(f_printHEADER_ITEM "$(grep -sEw "^x-frame-options:" ${s} | sed 's/x-frame-options:/=>/')")
p3p=$(grep -sEiw "^p3p:" ${s} | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | tail -1)
x_cross=$(grep -sEw "^x-permitted-cross-domain-policies" ${s} | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | sort -u)
access_origin=$(grep -sEw "^access-control-allow-origin:" ${s} | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | sort -u)
grep -sEoi "e-tag|access-control-allow-headers|access-control-expose-headers|cross-origin-embedder-policy|cross-origin-opener-policy|cross-origin-resource-policy" ${s} > $tempdir/headers_other;  grep -sEw "^x-ua-compatible:" ${s} | sed 's/^[ \t]*//;s/[ \t]*$//' | tail -1 >> $tempdir/headers_other
[[ -f $tempdir/headers_other ]] && [[ $(wc -l < $tempdir/headers_other) -gt 0 ]] && headers_other=$(cat $tempdir/headers_other | tr '[:space:]' ' '; echo '')
referrer_pol=$(grep -sEw "^referrer-policy:" ${s} | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | sort -u)
if [ -n "$referrer_pol" ]; then
if [[ $(f_countL "$referrer_pol") = "1" ]]; then
ref_pol_value=$(echo "$referrer_pol" | tr '[:space:]' ' '; echo '')
elif [[ $(f_countL "$referrer_pol") -gt "1" ]]; then
ref_pol_value=$(grep -sEw "^referrer-policy:" ${s} | sed 's/referrer-policy:/=>/' | sed 's/^[ \t]*//;s/[ \t]*$//' |
tr '[:space:]' ' ' | sed 's/^ *//' | sed 's/^\=>//'); else
ref_pol_value="Empty string"; fi; fi
grep -sEw "^expect-ct:|^pragma:|^public-key-pins|^x-xss-protection:" ${s} > $tempdir/deprecated
grep -siow -m 1 "feature-policy" ${s} >> $tempdir/deprecated
grep -siow -m 1 "permissions-policy" ${s} >> $tempdir/deprecated
[[ -n "$strict_ts" ]] && echo -e "Strict-Transport-Security:  $strict_ts" || echo -e "Strict-Transport-Security:  NA"
[[ -n "$c_pol" ]] || echo -e "Content-Security-Policy:    NA"
[[ -n "$c_control" ]] && echo -e "Cache-Control:              $c_control" || echo -e "Cache-Control:              NA"
[[ -n "$clear_data" ]] && echo -e "Clear-Site-Data:            $clear_data" || echo -e "Clear-Site-Data:            NA"
[[ -n "$referrer_pol" ]] && echo -e "Referrer-Policy:            $ref_pol_value" || echo -e "Referrer-Policy:            NA"
[[ -n "$x_copt" ]] && echo -e "X-Content-Type-Options:     $x_copt" || echo -e "X-Content-Type-Options:     NA"
[[ -n "$x_frame" ]] && echo -e "X-Frame-Options:            $x_frame" || echo -e "X-Frame-Options:            NA"
[[ -n "$headers_other" ]] && [[ $(f_countW "$headers_other") -lt 3 ]] && echo -e "Other:                      $headers_other"
[[ -n "$cpol_objects" ]] && echo -e "\n\nContent-Security-Policy Objects:\n\n$cpol_objects"
[[ -n "$rep_objects" ]] && echo -e "\n\nContent-Security-Policy-REPORT-ONLY Obj:\n\n$rep_objects"
[[ -n "$access_origin" ]] && echo -e "\nAccess-Control-Allow-Origin:\n\n$access_origin" && aco_count=$(f_countW "$access_origin") 
[[ -n "$x_cross" ]] && echo -e "\n\nX-Permitted-Cross-Domain-Policies:\n\n$x_cross"
[[ -n "$p3p" ]] && echo -e "\n\nP3P:\n$p3p"
[[ -n "$headers_other" ]] && [[ $(f_countW "$headers_other") -gt 2 ]] && echo -e "\n\nOther:\n\n$headers_other"
[[ -f $tempdir/deprecated ]] && [[ $(wc -w < $tempdir/deprecated) -gt 0 ]] && echo -e "\n\nDeprecated:\n" && cat $tempdir/deprecated
ts_count=$(grep -sEiowc "^strict-transport-security:" ${s}); xf_count=$(grep -sEoiwc "^x-frame-options:" ${s})
cpol_count=$(grep -sEoiwc "^content-security-policy:" ${s}); cpolr_count=$(grep -sEoiwc "^content-security-policy-report-only:" ${s})
[[ $ts_count -eq 0 ]] && echo -e "\n\n! Strict-Transport-Security:\n\n  Not set" >> $tempdir/h_issues
[[ $ts_count -gt 1 ]] && echo -e "\n\n! Strict-Transport-Security:\n\n  Duplicate header" >> $tempdir/h_issues
if [ -n "$access_origin" ] && [[ $aco_count -eq 1 ]]; then 
[[ $(echo "$access_origin" | grep -oc '\*') -eq 1 ]] && echo -e "\n\n! Access-Control-Allow-Origin:\n\n  Lax CORS policy  (at least for common use cases)" >> $tempdir/h_issues; fi
if [[ $cpol_count -eq 0 ]] && [[ $cpolr_count -eq 0  ]]; then
if [ $xf_count -eq 0 ]; then 
echo -e "\n\n! Content-Security-Policiy: CSP header missing\n\n  Consider setting CSP directives for protection against attacks (e.g. XSS, clickjacking)" >> $tempdir/h_issues; else
echo -e "\n\nX-Frame-Options:\n\n  Replacing X-Frame Options with CSP directives (e.g. frame-ancestors) is recommended practice" >> $tempdir/h_issues; fi; fi 
}
f_HEADERS(){
local s="$*"; f_HEADLINE "$1  | HTTP HEADERS |  $(date)"
if [ -f $tempdir/verb ]; then
ips_redir=$(grep -E "Connected to" $tempdir/verb | awk '{print ">"$4}' | tr -d '()' | sed 's/^[ \t]*//;s/[ \t]*$//' | tr -d ' ')
print_ips_redir=$(echo "$ips_redir" | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' | tr -d ' ' | sed 's/>/>  /g' |
sed 's/^ *//' | sed 's/^\>//' | sed 's/>/ >/g'); echo -e "\n$print_ips_redirs\n"; else
echo ''; fi; cat $tempdir/headers | sed 's/^ *//'
}
f_printHEADER_ITEM(){
echo "$1" | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' | sed 's/^ *//' | sed 's/^\=>//' | sed 's/=> /=>/g' | sed 's/ =>/=>/g' |
sed 's/=>/ => /g' | sed 's/^ *//'; echo ''
}
#-------------------------------  AUTONOMOUS SYSTEMS / PREFIXES / BGP/RPKI STATUS  -------------------------------

f_AS_INFO(){
local s="$*"; asn=$(echo $s | tr -d 'AS' | tr -d 'as' | tr -d ' '); unset query_status; unset as_set; option_detail="2"
echo ''; as_set=$(f_AS_SET "$s"); [[ -n "$as_set" ]] && echo -e "$as_set\n"
curl -s -m 20 --location --request GET "https://stat.ripe.net/data/as-overview/data.json?resource=${asn}" > $tempdir/asov.json
dig +short as$asn.asn.cymru.com TXT | tr -d '"' | sed 's/^[ \t]*//;s/[ \t]*$//' > $tempdir/cyas
as_rir=$(cut -s -d '|' -f 3 $tempdir/cyas | sed 's/^[ \t]*//;s/[ \t]*$//'); export rir=$(echo "$as_rir" | sed 's/ripencc/ripe/')
print_rir=$(f_toUPPER="$(echo "$as_rir" | sed 's/ripencc/ripe ncc/')"); as_cc=$(cut -s -d '|' -f 2 $tempdir/cyas | tr -d ' ')
alloc_date=$(cut -s -d '|' -f 4 $tempdir/cyas | sed 's/^[ \t]*//;s/[ \t]*$//' | cut -d '-' -f -2)
as_status=$(jq -r '.data.announced' $tempdir/asov.json | sed 's/true/Active/' | sed 's/false/Inactive/')
curl -s -m 10 --location --request GET "https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=${asn}" > $tempdir/ac.json
abuse_c=$(jq -r '.data.abuse_contacts[]?' $tempdir/ac.json | tr '[:space:]' ' '; echo '')
if [ $rir = "arin" ] ; then
timeout 20 whois -h whois.arin.net a $asn > $tempdir/whois_as
as_number=$(grep -E "^ASNumber:" $tempdir/whois_as | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
elif [ $rir = "lacnic" ] ; then
timeout 20 whois -h whois.lacnic.net as$asn > $tempdir/whois_as; else
timeout 20 whois -h whois.$rir.net -- "-B as$asn" > $tempdir/whois_as; fi
curl -s -m 10 --location --request GET "https://stat.ripe.net/data/as-routing-consistency/data.json?resource=${asn}" > $tempdir/cons.json
[[ -f $tempdir/cons.json ]] && pfx_total=$(jq -r '.data.prefixes[].prefix?' $tempdir/cons.json | wc -w) || pfx_total="0"
if [[ $pfx_total -gt "0" ]]; then
curl -s -m 10 --location --request GET "https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS${asn}" > $tempdir/nb.json
pfx_cons=$(jq -r '.data.prefixes[] | {RIS: .in_bgp, IRR: .in_whois, PFX: .prefix}' $tempdir/cons.json | tr -d '{",}' | sed 's/^ *//' |
sed '/^$/d' | tr '[:space:]' ' ' | sed 's/RIS:/\nRIS >/g' | sed 's/IRR:/| IRR >/g' | sed 's/PFX:/ |/g')
v4_all=$(echo "$pfx_cons" | awk '{print $NF}' | grep -v ':'); v4_ris=$(echo "$pfx_cons" | grep 'RIS > true' | awk '{print $NF}' | grep -v ':')
v4_low_vis=$(echo "$pfx_cons" | grep 'RIS > false' | awk '{print $NF}' | grep -v ':')
v6_all=$(echo "$pfx_cons" | awk '{print $NF}' | grep ':'); v6_ris=$(echo "$pfx_cons" | grep 'RIS > true' | awk '{print $NF}' | grep ':')
v6_low_vis=$(echo "$pfx_cons" | grep 'RIS > false' | awk '{print $NF}' | grep ':')
v4_all_count=$(f_countW "$v4_all"); v4_ris_count=$(f_countW "$v4_ris"); v4_low_count=$(f_countW "$v4_low_vis")
v6_all_count=$(f_countW "$v6_all"); v6_ris_count=$(f_countW "$v6_ris"); v6_low_count=$(f_countW "$v6_low_vis")
nbc_uniq=$(jq -r '.data.neighbour_counts.unique' $tempdir/nb.json); nbc_left=$(jq -r '.data.neighbour_counts.left' $tempdir/nb.json)
nbc_right=$(jq -r '.data.neighbour_counts.right' $tempdir/nb.json); nbc_unc=$(jq -r '.data.neighbour_counts.uncertain' $tempdir/nb.json)
nb_right=$(jq -r '.data.neighbours[] | select(.type == "right") | .asn' $tempdir/nb.json)
nb_left=$(jq -r '.data.neighbours[] | select(.type == "left") | .asn' $tempdir/nb.json); fi
if [ $as_status = "Active" ]; then
curl -s -m 20 "https://www.peeringdb.com/api/net?asn__in=$asn" > $tempdir/peeringdb_asn.json
object_id=$(jq -r '.data[].id?' $tempdir/peeringdb_asn.json)
if [ -n "$object_id" ]; then
irr_as_set=$(jq -r '.data[].irr_as_set' $tempdir/peeringdb_asn.json | sed '/null/d')
as_aka=$(jq -r '.data[].aka' $tempdir/peeringdb_asn.json | sed '/null/d')
as_scope=$(jq -r '.data[].info_scope?' $tempdir/peeringdb_asn.json | sed '/null/d')
as_type=$(jq -r '.data[].info_type?' $tempdir/peeringdb_asn.json | sed '/null/d')
traffic_volume=$(jq -r '.data[].info_traffic' $tempdir/peeringdb_asn.json | sed '/null/d')
traffic_ratio=$(jq -r '.data[].info_ratio' $tempdir/peeringdb_asn.json | sed '/null/d')
[[ -z "$traffic_volume" ]] && traffic_volume="unknown"
as_website=$(jq -r '.data[].website' $tempdir/peeringdb_asn.json | sed '/null/d')
pol_general=$(jq -r '.data[].policy_general?' $tempdir/peeringdb_asn.json | sed '/null/d')
[[ -n "$pol_general" ]] || pol_general="-"
looking_glass=$(jq -r '.data[].looking_glass' $tempdir/peeringdb_asn.json | sed '/null/d')
route_server=$(jq -r '.data[].route_server' $tempdir/peeringdb_asn.json | sed '/null/d')
policy_url=$(jq -r '.data[].policy_url?' $tempdir/peeringdb_asn.json | sed '/null/d')
ix_count=$(jq -r '.data[].ix_count?' $tempdir/peeringdb_asn.json | sed '/null/d')
if [ -n "$ix_count" ] && [[ $ix_count -gt 0 ]]; then
curl -s "https://www.peeringdb.com/api/net/${object_id}" > $tempdir/ix_as.json
ix_results=$(jq -r '.data[] | .netixlan_set[] | {IXID: .ix_id, IXNAME: .name}?' $tempdir/ix_as.json | tr -d '{",}' | sed '/^$/d' |
sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/IXID:/\[/' | sed 's/IXNAME:/\],IXNAME~/' | cut -d ':' -f -1 | awk -F'--' '{print $1}' |
tr -d ' ' | tr '[:space:]' ' ' | sed 's/\[/\n[ /g' | sort -u | awk -F'IXNAME~' '{print $2,$1}' | sort -t '[' -k 1 | tr -d ' ' |
tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/,$//' | fmt -w 70 | sed 's/\[/ \[/g' | sed 's/\],/\], /g' | sed G; echo '')
if [ -n "$ix_results" ]; then
ix_presence=$(echo -e "\n\n$ix_results"); else
ix_presence="NA"; fi; ix_member="true"; else
ix_member="false"; fi; fi; fi
asname=$(jq -r '.data.holder' $tempdir/asov.json | awk -F' ' '{print $1}'); as_cc=$(cut -d '|' -f 2 $tempdir/cyas | tr -d ' ')
echo ''; f_Long ; echo "[+]  AS $asn - $asname  |  DATE:  $file_date"; f_Long
echo "[@]: $abuse_c" ; echo -e "____\n"
echo -e "\nName:             $(jq -r '.data.holder' $tempdir/asov.json), $as_cc"
[[ $rir = "arin" ]] && [[ ${as_number} =~ "-" ]] && echo -e "\nAS Number:        $as_number"
if [ $as_status = "Active" ]; then
[[ -n "$as_aka" ]] && echo -e "\nAka:              $as_aka"
if [ -n "$as_type" ]; then
[[ -n "$as_scope" ]] && echo -e "\nType:             $as_type;  Scope: $as_scope" || echo -e "\nType:             $as_type"; fi
[[ -n "$as_aka" ]] && [[ -n "$as_type" ]] && echo ''; [[ -n "$irr_as_set" ]] && echo -e "\nIRR AS-Set:       $irr_as_set"; fi
echo -e "\nStatus:           $as_status | Allocated: $alloc_date | $as_cc"; echo ''
if [ $as_status = "Active" ]; then
[[ -n "$route_server" ]] || [[ -n "$looking_glass" ]] || [[ -n "$policy_url" ]] && echo ''
[[ -n "$route_server" ]] && echo "Route Server:     $route_server"
[[ -n "$looking_glass" ]] && echo "LookingGlass:     $looking_glass"; [[ -n "$as_website" ]] && echo "Website:          $as_website"
[[ -n "$policy_url" ]] && echo "Policy URL:       $policy_url"; echo ''; f_Long
if [ -n "$traffic_volume" ] || [ -n "$traffic_ratio" ]; then
echo -e "\nTRAFFIC\n"; echo -e "Volume:  $traffic_volume;  Ratio:  $traffic_ratio\n" || echo -e "No data"; fi
echo -e "\nPEERING\n"
echo -e "Peers:  $nbc_uniq  ($nbc_left left, $nbc_right right, $nbc_unc uncertain) | IX Presence: $ix_member | Policy:  $pol_general"; fi
[[ $as_status = "Inactive" ]] && f_Long || echo ''
echo -e "\nPREFIXES\n"
echo -e "IPv4:  $v4_all_count"
if [[ $v4_all_count -gt 0 ]]; then
echo -e "\nVisibility:  Medium/high: $v4_ris_count | Low/NA: $v4_low_count\n"; fi
echo -e "IPv6:  $v6_all_count"
if [[ $v6_all_count -gt 0 ]]; then
echo -e "\nVisibility:  Medium/high: $v6_ris_count | Low/NA: $v6_low_count"; fi
f_POC "$tempdir/whois_as" | fmt -s -w 100
if [ $as_status = "Active" ]; then
if [[ $ix_count -gt 0 ]]; then
echo ''; f_HEADLINE2 "IX PRESENCE [IX-ID]\n"; if [[ $ix_count -lt 52 ]]; then
echo -e "$ix_presence\n"; else
echo -e "\nMemberships: $ix_count\n\nOutput written to file"
ix_out="${outdir}/AS$s.IX.${file_date}.txt"; echo '' > $ix_out
f_HEADLINE "AS $s IX PRESENCE [IX-ID] | $file_date" >> $ix_out; echo -e "Memberships: $ix_count\n" >> $ix_out
echo -e "\n$ix_presence\n" | fmt -s -w 75 | sed G >> $ix_out; fi; fi; fi
if [[ $pfx_total -gt "0" ]]; then
echo ''; f_HEADLINE2 "BGP PREFIXES\n"
[[ -n "$v4_ris" ]] && echo -e "\n -- IPv4 --\n\n" && echo "$v4_ris" | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -s -w 55 | sed G
[[ -n "$v6_ris" ]] && echo -e "\n -- IPv6 --\n\n" && echo "$v6_ris" | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -s -w 55 | sed G
if [ -n "$v4_low_vis" ] || [ -n "$v6_low_vis" ]; then
echo ''; f_HEADLINE2 "LOW VISIBILITY / NOT ANNOUNCED\n\n"
[[ -n "$v4_low_vis" ]] && echo "$v4_low_vis" | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -s -w 55 | sed G
[[ -n "$v6_low_vis" ]] && echo "$v6_low_vis" | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -s -w 55 | sed G; fi
if [ -n "$nb_left" ] || [ -n "$nb_right" ]; then
if [[ $nbc_left -gt 1 ]] || [[ $nbc_right -gt 1 ]]; then
print_peers="${outdir}/AS$s.PEERS.${file_date}.txt"
print_nb_left=$(echo "$nb_left" | sort -ug | tr '[:space:]' ' '  | sed 's/ /  /g' | sed 's/^[ \t]*//;s/[ \t]*$//' |
fmt -w 60 | sed G)
print_nb_right=$(echo "$nb_right" | sort -ug | tr '[:space:]' ' '  | sed 's/ /  /g' | sed 's/^[ \t]*//;s/[ \t]*$//' |
fmt -w 60 | sed G)
echo '' > $print_peers; f_HEADLINE "AS $s NEIGHBOURS" >> $print_peers
[[ -n "$print_nb_left" ]] && echo -e "\nLEFT\n\n$print_nb_left\n" >> $print_peers
[[ -n "$print_nb_right" ]] && echo -e "\nRIGHT\n\n$print_nb_right\n" >> $print_peers
if [[ $nb_count_left -lt 120 ]] && [[ $nb_count_right -lt 120 ]]; then
[[ -n "$print_nb_left" ]] && echo ' ' && f_HEADLINE2 "PEERS (LEFT)\n\n" && echo "$print_nb_left"
[[ -n "$print_nb_right" ]] && echo ' ' && f_HEADLINE2 "PEERS (RIGHT)\n\n" && echo "$print_nb_right"; fi; fi; fi; fi
}
f_AS_SET(){
local s="$*"; whois -h whois.radb.net -- "as-$s" > $tempdir/as_set
if [ -f $tempdir/as_set ] && [[ $(grep -c 'as-set:' $tempdir/as_set) -gt 0 ]]; then
set_num=$(grep -E "^as-set:" $tempdir/as_set | awk '{print $NF}' | tr -d ' ')
set_members=$(grep -E "^members:" $tempdir/as_set | awk '{print $NF}' | tr -d ' ' | tr '[:space:]' ' ')
set_source=$(grep -E "^source:" $tempdir/as_set | awk '{print $NF}' | tr -d ' ')
mnt_lower=$(grep -E "^mnt-lower:" $tempdir/as_set | awk '{print $NF}' | tr -d ' ')
[[ $option_detail = "1" ]] && echo -e "\nAS-Set:\n" || f_HEADLINE "AS-SET"
if [ -n "$mnt_lower" ]; then
echo -e "$set_num | Members: $set_members | MNT-Lower: $mnt_lower | Source: $set_source"; else
echo -e "$set_num | Members: $set_members | Source: $set_source"; fi; fi
}
f_AS_SHORT(){
local s="$*";  unset as_org; unset as_orgid; unset as_name; unset as_rir; unset as_set
[[ -f $tempdir/asov.json ]] && rm $tempdir/asov.json
curl -s -m 10 --location --request GET "https://stat.ripe.net/data/as-overview/data.json?resource=${s}" > $tempdir/asov.json
[[ $domain_enum = "false" ]] && as_set=$(f_AS_SET "$s"); announced=$(jq -r '.data.announced' $tempdir/asov.json)
as_sum=$(dig +short as${s}.asn.cymru.com TXT | tr -d '"' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/ripencc/ripe/')
as_rir=$(echo "$as_sum" | cut -d '|' -f 3 | tr -d ' '); as_cc=$(echo "$as_sum" | cut -d '|' -f 2 | tr -d ' ')
alloc=$(echo "$as_sum" | cut -d '|' -f 3,4 | tr [:lower:] [:upper:] | cut -d '-' -f -2 | sed 's/^[ \t]*//;s/[ \t]*$//')
as_name=$(jq -r '.data.holder' $tempdir/asov.json | cut -d ' ' -f 1)
if [ $as_rir = "lacnic" ]; then
whois -h whois.lacnic.net as$s > $tempdir/lacnic_as; as_abuse=$(f_printLACNIC_ABUSE_C "$tempdir/lacnic_as"); else
as_abuse=$(curl -s -m 10 --location --request GET "https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=${s}" |
jq -r '.data.abuse_contacts[]' | tr '[:space:]' ' ' ; echo '')
if [ $as_rir = "arin" ]; then
as_org=$(whois -h whois.pwhois.org "registry source-as=$s"  | grep -E -m 1 "^Org-Name:"  | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//'); else
as_org=$(jq -r '.data.holder' $tempdir/asov.json | awk -F '-' '{print $NF}' | sed 's/^[ \t]*//;s/[ \t]*$//'); fi; fi
if [ $domain_enum = "true" ]; then
echo -e "\nAS $s"; else
if [[ $choice = "w1" ]] || [[ $choice = "w3" ]]; then
[[ -n "$as_set" ]] && echo -e "\n$s"  || echo -e "\nAS $s\n"; else 
[[ -n "$as_set" ]] && f_HEADLINE2 "$s\n" && echo -e "$as_set\n" || f_HEADLINE2 "AS $s\n"; fi
[[ -n "$as_set" ]] && [[ -n "$alloc" ]] && echo -e "\nAut-Num: $s\n"; fi
[[ -n "$as_org" ]] && echo -e "\n$as_name - $as_org, $as_cc\n" || echo -e "\n$as_name, $as_cc\n"
[[ -n "$announced" ]] && echo -e "$alloc | Active: $announced | $as_abuse\n" || echo -e "$alloc | $as_abuse\n"
[[ $domain_enum = "true" ]] && [[ $as_rir = "lacnic" ]] && echo $s >> $tempdir/lacnic_asns
}
f_BGP_UPDATES(){
local p="$*"
curl -s --location --request GET "https://stat.ripe.net/data/bgp-update-activity/data.json?resource=${p}&num_hours=24" > $tempdir/update.json
announcements=$(jq -r '.data.updates[] | .announcements' $tempdir/update.json)
if [ -n "$announcements" ]; then
f_Long; echo -e "$p   BGP UPDATES  (past 24 hrs)\n\n"; echo "$p"
jq -r '.data.updates[] | {time: .starttime, withdrawals: .withdrawals, announcements: .announcements}' $tempdir/update.json | tr -d '{"}' |
sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' | sed 's/T/  /g' | tr '[:space:]' ' ' | sed 's/time: /\n/g' | sed 's/,/  | /g' |
sed 's/withdrawals:/withdrawals: /' | sed 's/announcements:/announcements: /'; echo ''; fi
}
f_getASNAME(){
local asnum="$*"; if [ $target_type = "prefix" ]; then
asname=$(jq -r '.data.asns[0].holder' $tempdir/pov.json); else
asname=$(curl -s -m 7 --location --request GET "https://stat.ripe.net/data/as-overview/data.json?resource=${asnum}" | jq -r '.data.holder'); fi
as_cc=$(dig +short as$asnum.asn.cymru.com TXT | cut -d '|' -f 2 | sed 's/^[ \t]*//;s/[ \t]*$//')
if [ $target_type = "net" ] || [ $target_type = "default" ] || [ $target_type = "hop" ]; then
echo -e "\nASN:          $asnum,  $asname, $as_cc"
elif [ $target_type = "prefix" ]; then
echo -e "$asnum, $asname, $as_cc\n"; else
echo "AS $asnum, $asname, $as_cc"; fi
}
f_ROUTE(){
local s="$*"; unset as; unset prfx
if [ $target_type = "dnsrec" ] || [ $target_type = "nic" ] || [ $target_type = "web" ]; then
curl -s -m 10 --location --request GET "https://stat.ripe.net/data/network-info/data.json?resource=${s}" > $tempdir/net.json
prfx=$(jq -r '.data.prefix' $tempdir/net.json); as=$(jq -r '.data.asns[0]' $tempdir/net.json)
elif [ $target_type = "prefix" ]; then
announced=$(jq -r '.data.announced' $tempdir/pov.json); if [ $announced = "false" ]; then
num_related=$(jq -r '.data.actual_num_related' $tempdir/pov.json)
num_filtered=$(jq -r '.data.num_filtered_out' $tempdir/pov.json)
related_pfx=$(jq -r '.data.related_prefixes[]' $tempdir/pov.json | sed '/null/d')
echo -e "\nPrefix is not announced or has very low visibility.\n"
[[ -n "$related_pfx" ]] && echo -e "\nRELATED\n\nNum related: $num_related (actual), $num_filtered (low vis.)\n\n$print_related"; else
as=$(jq -r '.data.asns[0].asn' $tempdir/pov.json); prfx=$(jq -r '.data.resource' $tempdir/pov.json); fi; else
netn=$(grep -sE -m 1 "^Net-Name:" $tempdir/pwhois | awk '{print $NF}' | tr -d ' ')
prfx=$(grep -E "^Prefix:" $tempdir/pwhois | awk '{print $NF}')
as=$(grep -E "^Origin-AS:" $tempdir/pwhois | awk '{print $NF}' | tr -d 'AS' | sed 's/^[ \t]*//;s/[ \t]*$//'); fi
if [ -n "$as" ]; then
curl -s -m 5 --location --request GET "https://stat.ripe.net/data/rpki-validation/data.json?resource=$as&prefix=$prfx" > $tempdir/rpki.json
rpki_status=$(jq -r '.data.status' $tempdir/rpki.json)
if [ $target_type = "prefix" ]; then
vis=$(f_VIS "${prfx}"); echo -e "PREFIX\n\n$prfx  | $vis\n\n"; echo -e "ASN\n"; f_getASNAME "$as"; f_RPKI
elif [ $target_type = "dnsrec" ] || [ $target_type = "nic" ] || [ $target_type = "web" ]; then
echo -e "*> $prfx - ROA: $rpki_status - $(f_getASNAME "$as")"; else
if [ $rir = "arin" ] || [ $rir = "lacnic" ]; then
echo -e "\nBGP:          $prfx,  ROA: $rpki_status"; else
nname_wh=$(jq -r '.data.records[0]? | .[] | select (.key=="netname") | .value' $tempdir/whois.json)
nname_pwh=$(grep -sE -m 1 "^Net-Name:" $tempdir/pwhois | awk '{print $NF}' | tr -d ' ')
if [ $nname_wh = $nname_pwh ]; then
echo -e "\nBGP:          $prfx,  ROA: $rpki_status"; else
echo -e "\nBGP:          $prfx | $netn | ROA: $rpki_status"; fi; fi; f_getASNAME "$as"; fi; else
echo -e "\nBGP:          false"; fi
}
f_ROUTE_CONS(){
local s="$*"
curl -s -m 7 --location --request GET "https://stat.ripe.net/data/prefix-routing-consistency/data.json?resource=${s}" > $tempdir/cons.json
if [ -f $tempdir/cons.json ]; then
f_HEADLINE2 "BGP/RIS - WHOIS CONSISTENCY\n\n"
jq -r '.data.routes[] | {PFX: .prefix, RIS: .in_bgp, WHOIS: .in_whois, ASNUM: .origin, ASNAME: .asn_name}' $tempdir/cons.json |
tr -d '{",}' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d'| tr '[:space:]' ' ' | sed 's/PFX: /\n/g' |
sed 's/RIS:/| RIS:/' | sed 's/WHOIS:/| WHOIS:/' | sed 's/ASNUM:/| AS/' | sed 's/ASNAME:/-/' | grep '|' > $tempdir/cons
grep -sEw "RIS: true \| WHOIS: true" $tempdir/cons > $tempdir/cons_sorted
grep -sEw "RIS: false \| WHOIS: true" $tempdir/cons >> $tempdir/cons_sorted
grep -sEw "RIS: true \| WHOIS: false" $tempdir/cons >> $tempdir/cons_sorted
grep -sEw "RIS: false \| WHOIS: false" $tempdir/cons >> $tempdir/cons_sorted
cat $tempdir/cons_sorted | sed '/^$/d' | sed 's/| /\n\n/' | sed '/|/G' | sed 's/false/false !/g'; fi
}
f_RPKI(){
rpki_status=$(jq -r '.data.status' $tempdir/rpki.json); echo -e "\nRPKI STATUS (ROAs)\n"
if [ $rpki_status = "unknown" ]; then
echo -e "$rpki_status\n"; else
roa_pfx=$(jq -r '.data.validating_roas[0].prefix' $tempdir/rpki.json)
roa_or=$(jq -r '.data.validating_roas[0].origin' $tempdir/rpki.json); max_len=$(jq -r '.data.validating_roas[0].max_length' $tempdir/rpki.json)
valid=$(jq -r '.data.validating_roas[0].validity' $tempdir/rpki.json); echo -e "$valid >  $roa_pfx >  $roa_or  > max. /$max_len\n"; fi
}
f_VIS(){
local p="$*"; pfx_ip=$(echo $p | cut -d '/' -f 1)
curl -s "https://stat.ripe.net/data/routing-status/data.json?resource=${p}" > $tempdir/bgp.json
if [[ ${pfx_ip} =~ $REGEX_IP4 ]] ; then
visibility=$(jq -r '.data.visibility.v4.ris_peers_seeing' $tempdir/bgp.json)
peers_total=$(jq -r '.data.visibility.v4.total_ris_peers' $tempdir/bgp.json); else
visibility=$(jq -r '.data.visibility.v6.ris_peers_seeing' $tempdir/bgp.json)
peers_total=$(jq -r '.data.visibility.v6.total_ris_peers' $tempdir/bgp.json); fi
f_seen=$(jq -r '.data.first_seen.time' $tempdir/bgp.json | cut -d 'T' -f 1)
f_seen_origin=$(jq -r '.data.first_seen.origin' $tempdir/bgp.json)
if [ $target_type = "hop" ]; then
echo "Visibility:  $visibility/$peers_total | First seen: $f_seen  ($f_seen_origin)"; else 
echo "Visibility (RIS):  $visibility/$peers_total | First seen: $f_seen  ($f_seen_origin)"; fi
}

#-------------------------------  TRACEROUTING & PING  -------------------------------

f_MTR(){
local s="$*"; echo ''; f_dnsCHAIN "${s}"; echo ''; f_HEADLINE2 "$s  MTR ($mtr_info)\n\n"
sudo ${PATH_mtr} ${mtr_array[@]} --mpls -w -o "  L  D  A  W  M  X" ${s} | sed '/Start:/G' | sed '/Javg/G' > $tempdir/mtr.txt
cat $tempdir/mtr.txt; echo ''; f_Short; echo -e "AVG = average RTT in ms; Wrst = worst RTT; \nJavg = average jitter; Jmax = max jitter\n"
}
f_MTR_HTAPI(){
local s="$*"; echo ''; f_dnsCHAIN "${s}"; echo ''; f_HEADLINE2 "$s\n"
curl -s https://api.hackertarget.com/mtr/?q=${s}${api_key_ht} > $tempdir/mtr_ht
sed '/HOST:/{x;p;x;G}' $tempdir/mtr_ht; echo -e "\n Source > hackertarget.com IP API\n"
}
f_nmapGEOTRACE(){
local s="$*"; echo ''
sudo ${PATH_nmap} ${trace_array[@]} --traceroute --script=traceroute-geolocation 2>/dev/null $s |
grep -E "Nmap scan report|Host is|\||\|_" | grep -v 'traceroute-geolocation:' | sed '/Host is/G' |
sed '/GEOLOCATION/{x;p;x;G}' | tr -d '|_' | sed 's/^ *//' | sed '/Nmap scan report/{x;p;x;G}' |
sed 's/Nmap scan report for //g' > $tempdir/geotrace
f_dnsCHAIN "${s}"; echo ''; f_HEADLINE2 "$s\n"; cat $tempdir/geotrace
}
f_PATH_MTU(){
local s="$*"; echo ''; sudo ${PATH_nmap} -R --resolve-all -sS -sU -Pn -p ${ports_mtu} --open --script=path-mtu.nse $s 2> /dev/null |
grep -E "scan report|\||\|_" | sed 's/Nmap scan report for/\n*/' | tr -d '|_' | sed 's/^ *//' | sed 's/path-mtu:/\n /'
}
f_PING(){
if [ $target_type = "web" ]; then
if [[ $1 =~ $REGEX_IP4 ]]; then
${PATH_nping} --safe-payloads --tcp-connect -p 80 -c 5 $1 > $tempdir/np; else
${PATH_nping} -6 --safe-payloads --tcp-connect -p 80 -c 5 $1 > $tempdir/np; fi; fi
timeout 5 ping -c 5 $1 > $tempdir/ipg; [[ -f $tempdir/np ]] && f_printNPING
icmp_packets=$(grep packets $tempdir/ipg | cut -d ',' -f -2 | sed 's/packets transmitted/sent/' | sed 's/received/ok/' |
sed 's/^[ \t]*//;s/[ \t]*$//')
if [ -n "$icmp_packets" ]; then
icmp_avg=$(sed -n '/---/,$p' $tempdir/ipg | grep 'rtt' | cut -d '=' -f 2 | awk -F'/' '{print $2}' | tr -d ' ')
icmp_max=$(sed -n '/---/,$p' $tempdir/ipg | grep 'rtt' | cut -d '=' -f 2 | awk -F'/' '{print $3}' | tr -d ' ')
icmp_mdev=$(sed -n '/---/,$p' $tempdir/ipg | grep 'rtt' | cut -d '=' -f 2 | awk -F'/' '{print $4}' | tr -d 'ms' | tr -d ' ')
actual_ttl=$(grep -so "ttl=.[0-9]${2,3}" $tempdir/ipg | cut -s -d '=' -f 2 | tail -1 | tr -d ' ')
num_hops=$(($default_ttl - $actual_ttl))
echo -e "\nICMP Ping:   $icmp_packets | Avg: $icmp_avg ms | Mdev: $icmp_mdev ms | Hops: $num_hops"; else
echo -e "\nICMP Ping:   failed"; fi
}
f_printNPING(){
if [ -f $tempdir/np ]; then
np_conn=$(grep 'Failed' $tempdir/np | awk -F'attempts:' '{print $2}' | awk '{print $1}' | tr -d ' ')
np_ok=$(grep Failed: $tempdir/np | awk -F'connections:' '{print $2}' | awk '{print $1}' | tr -d ' ')
np_avg=$(grep 'Avg rtt:' $tempdir/np | awk -F'Avg rtt:' '{print $2}' | awk '{print $1}' | tr -d ' ')
np_max=$(grep 'Max rtt:' $tempdir/np | awk -F'Max rtt:' '{print $2}' | awk '{print $1}' | tr -d ' ')
np_target=$(grep -m 1 'SENT' $tempdir/np | awk -F'>' '{print $2}' | tr -d ' ')
echo -e "\nTCP Ping:    $np_conn conn, $np_ok ok | Avg: $np_avg | Max: $np_max  ($np_target)" | sed 's/ms/ ms/g'; fi
}
f_TRACEPATH(){
local s="$*"; echo ''; f_dnsCHAIN "${s}"; echo ''; f_HEADLINE2 "$s\n"
${PATH_tracepath} ${tpath_array[@]} $s | sed 's/^ *//' > $tempdir/trace; cat $tempdir/trace |
sed '/Resume/i \\n___________________________________\n'; echo ''
}
f_TRACEROUTE_HEADER(){
local hl="$*"; echo ''; f_HEADLINE "$hl | $(date -R)"; echo ''; f_CLIENT_INFO
}

#-------------------------------  SERVICE BANNERS, NMAP   -------------------------------

f_BANNERS(){
local s="$*" ; curl -s https://api.hackertarget.com/bannerlookup/?q=${s}${api_key_ht} > $tempdir/banners.json
if [ -f $tempdir/banners.json ]; then
f_HEADLINE2 "$s BANNERS (SOURCE: HACKERTARGET:COM)\n"
jq -r '{IP: .ip, FTP: .ftp, SSH: .ssh, Telnet: .telnet,  RDP: .rdp, http_Server: .http.server, http_Title: .http.title, https443_Server: .https443.server, https443_Title: .https443.title, https443_CN: .https443.cn, https443_Org: .https443.o, http9090_Server: .http8080.server, http9090_Title: .http8080.title, https8553_Server: .https8443.server, https8553_Title: .https8443.title, https8553_CN: .https8443.cn}' $tempdir/banners.json | tr -d '{,"}' | sed 's/http_Server: null/http_Server: none\/unknown/g' | sed '/null/d' |
sed '/^$/d' | sed 's/^ *//' | sed '/^IP:/i nnnn' | tr '[:space:]' ' ' | sed 's/http_Title:/\n80\/HTTP Title:/g' |
sed 's/https443_Title:/\n443\/HTTPS Title:/g' | sed 's/https443_CN:/| CN:/g' | sed 's/https443_Org:/| Org:/g' |
sed 's/http9090_Title:/\nHTTP\/8080 Title:/g' | sed 's/https8553_Title:/\nHTTPS\/8443Title:/g' | sed 's/https85533_CN:/| CN:/g' |
sed 's/IP:/\n>IP:/g' | sed 's/FTP:/\nFTP:/g' | sed 's/SSH:/\nSSH:/g' | sed 's/Telnet:/\nTelnet:/g' | sed 's/RDP:/\nRDP:/g' |
sed 's/http9090_Server:/\n8080\/HTTP Server:/g' | sed 's/https443_Server:/\n443\/HTTPS Server:/g' |
sed 's/https85533_Server:/\n8443\/HTTPS\ Server:/g' | sed 's/http_Server:/\n80\/HTTP Server:/g' | sed 's/server: //g' |
sed 's/nnnn/\n/g' | sed 's/^ *//' > $tempdir/banners;
if [[ $(wc -w < $tempdir/banners) -gt 2 ]]; then
sed '/>IP:/G' $tempdir/banners | sed 's/>IP:/\n>/g' > $tempdir/netbanners
sed '/./,$!d' $tempdir/netbanners | sed 's/^/  /' | sed 's/  >/>/'; else
echo "No results (Source: hackertarget.com API)"; fi; fi
}
f_RUN_NMAP(){
local s="$*"; scan_target=$(echo $s | sed 's/http[s]:\/\///' | tr -d ' ')
scan_target_stripped=$(echo $scan_target  | cut -s -d '/' -f 1 | tr -d ' ')
if [[ ${scan_target} =~ $REGEX_IP4 ]] || [[ ${scan_target_stripped} =~ $REGEX_IP4 ]]; then
option_ipv="v4"; opt_v6=''
elif [[ ${scan_target} =~ ":" ]] || [[ ${scan_target_stripped} =~ ":" ]]; then
option_ipv="v6"; opt_v6="-6"; else
if ! [ $target_type = "web" ]; then
option_ipv="v4"; opt_v6=''; fi; fi
if [ $option_root = "y" ] ; then
sudo ${PATH_nmap} ${opt_v6} ${nmap_array[@]} ${ports} ${scan_target} ${scripts} ${script_args} 2>/dev/null > $tempdir/nmap.${option_ipv}.txt; else
${PATH_nmap} ${opt_v6} ${nmap_array[@]} ${ports} ${scan_target} ${scripts} ${script_args} 2>/dev/null > $tempdir/nmap.${option_ipv}.txt; fi
if [ $target_type = "web" ]; then
f_printNMAP2 "$tempdir/nmap.${option_ipv}.txt"; else
if [ $fw_enum = "false" ]; then
f_printNMAP1 "$tempdir/nmap.${option_ipv}.txt"; else
echo -e "\n$first_flag" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; f_printNMAP_FW "$tempdir/nmap.${option_ipv}.txt"
echo -e "Options: $(echo ${nmap_array2[@]})\n"
if [ $snd_scan = "true" ]; then
sudo ${PATH_nmap} ${opt_v6} ${nmap_array2[@]} ${ports} ${scan_target} 2>/dev/null > $tempdir/nmap2.${option_ipv}.txt
f_HEADLINE2 "$second_flag"; f_printNMAP_FW "$tempdir/nmap2.${option_ipv}.txt"
echo -e "Options: $(echo ${nmap_array2[@]})\n"
if [ $trd_scan = "true" ]; then
sudo ${PATH_nmap} ${opt_v6} ${nmap_array3[@]} ${ports} ${scan_target} 2>/dev/null > $tempdir/nmap3.${option_ipv}.txt
f_HEADLINE2 "$third_flag"; f_printNMAP_FW "$tempdir/nmap3.${option_ipv}.txt"; echo -e "Options: $(echo ${nmap_array3[@]})\n"
fi; fi; fi; fi
}
f_NMAP_BCAST(){
bcast=$(sudo ${PATH_nmap} --script=$1 2>/dev/null | grep '|' |
sed '/broadcast-/i \\n_______________________________________________________________________________\n\n' |
sed '/broadcast-/G' | sed 's/|_//' | sed 's/|//')
if [ -n "$bcast" ]; then
echo -e "$bcast\n"; else
echo -e "\n_______________________________________________________________________________\n$i\n\nNo response\n"; fi
}
f_NMAP_FWALK(){
local t="$*"; scan_target=$(echo $t  | cut -d '/' -f 1 | tr -d ' ')
[[ $option_nmap1 = "2" ]] && echo -e "FIREWALK ($scan_type)\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' || f_HEADLINE2 "FIREWALK ($scan_type)\n"
if [[ ${scan_target} =~ ":" ]]; then
option_ipv="v4"; opt_v6='-6'; else
opt_v6=''; fi; sudo ${PATH_nmap} ${opt_v6} ${fw_opts} ${scan_target} > $tempdir/fwalk
grep -E "^Nmap scan"  $tempdir/fwalk |
grep -E "^Nmap scan|^Host is|^Other addresses|^Not shown|^PORT|^[0-9]{1,5}|^\|_|^\||TRACEROUTE|HOP" $tempdir/fwalk |
sed 's/firewalk:/\n\nFIREWALK/' | sed 's/TRACEROUTE/\n\nTRACEROUTE/' | sed '/RTT/{x;p;x;G}' | tr -d '|_' |
sed '/Nmap scan/G' | sed 's/Nmap scan report for/\n>/' | sed '/PORT/{x;p;x;G}' | sed '/>/G' | sed 's/^ *//'; echo ''
}
f_NMAP_HTAPI(){
echo ''; f_HEADLINE2 "NMAP\n"; curl -s https://api.hackertarget.com/nmap/?q=$1${api_key_ht} | sed '/PORT/{x;p;x;G}'
echo -e "\nSource: hackertarget.com IP API\n"
}
f_printNMAP1(){
local s="$*";
grep -E "^Nmap scan report|Nmap done|rDNS|Not shown:|Host is|Host seems|PORT|/tcp|/udp|CVE.*|^[0-9]{1,2}|TRACEROUT|RTT|MAC|OS|Device type:|Running:|Distance:|Info:|\|" $s |
grep -E -v "MD5:|Subject Alternative|Public Key type:|Public Key bits:|Signature Algorithm:|Not valid before:|detection performed" |
sed '/Nmap scan report/i \_______________________________________________________________________________\n' | sed '/scan report/G' |
sed 's/Nmap scan report for //' | sed '/Not shown:/{x;p;x;}' | sed 's/Host is up/UP/' | sed 's/Not shown: //' | sed '/PORT/{x;p;x;G}' |
sed '/MAC Address:/{x;p;x;}' | sed '/Device type:/{x;p;x;}' | sed '/|_/G' | sed '/OS guesses:/{x;p;x;}' |
sed '/Nmap done/i \\n_______________________________________________________________________________\n' | fmt -s -w 120
}
f_printNMAP2(){
local s="$*"
grep -E "^Nmap scan report|Host is|Host seems|/tcp|/udp|CVE.*|MAC|OS|Device type:|Running:|Distance:|Info:|\|" $s |
sed '/Nmap scan report for/G' | sed 's/OS guesses:/OS guesses:\n/g' |
sed '/Nmap scan report/i \\n_______________________________________________________________________________\n' |
sed 's/Nmap scan report for/\n*/g' |  sed 's/Device type:/Device type:       /g' | sed 's/^|_//g' | sed 's/^|//g' |
sed '/\/tcp/i \\n-------------------------------------------------------------------------------\n\n' | sed '/CVE/G' | sed '/cpe:/G' |
sed '/\/udp/i \\n-------------------------------------------------------------------------------\n\n' | sed 's/^[ \t]*//;s/[ \t]*$//' |
sed '/Network Distance:/i \\n-------------------------------------------------------------------------------\n' |
sed 's/banner:/\nbanner:\n/g' | sed 's/Running:/\nRunning:    /g' | sed '/MAC Address:/{x;p;x;}' |
sed '/OS guesses:/i \\n\n-------------------------------------------------------------------------------\n' |
sed '/Device type:/i \\n\n-------------------------------------------------------------------------------\n' |
sed 's/OS details:/\nOS details:        /' | sed '/OS and Service detection performed/d' | sed 's/WAN IP:/\nWAN IP:/' |
sed 's/No exact OS matches/\n No exact OS matches/g' | sed '/No mobile version detected./d' |
sed 's/address-info:/\naddress-info:\n/g' | sed 's/Host script results:/\nHost script results:\n/g' |
sed 's/http-affiliate-id:/\n\nhttp-affiliate-id:\n/g' | sed 's/http-auth:/\n\nhttp-auth:\n/g' |
sed 's/http-auth-finder:/\n\nhttp-auth-finder:\n/g' | sed 's/http-aspnet-debug:/\n\nhttp-aspnet-debug:\n/g' |
sed 's/http-backup-finder:/\n\nhttp-backup-finder:\n/g' | sed 's/http-cookie-flags:/\n\nhttp-cookie-flags:\n/g' |
sed 's/http-cors:/\n\nhttp-cors:\n/g' | sed 's/http-cross-domain-policy:/\n\nhttp-cross-domain-policy:\n/g' |
sed 's/http-csrf:/\n\nhttp-csrf:\n/g' | sed 's/http-dombased-xss:/\n\nhttp-dombased-xss:\n/g' | sed 's/http-enum:/\n\nhttp-enum:\n/g' |
sed 's/http-jsonp-detection:/\n\nhttp-jsonp-detection:\n/g' | sed 's/http-malware-host:/\n\nhttp-malware-host:\n/g' |
sed 's/http-methods:/\n\nhttp-methods:\n/g' | sed 's/http-mobileversion-checker:/\n\nhttp-mobileversion-checker:\n/g' |
sed 's/http-open-redirect:/\n\nhttp-open-redirect:\n/g' | sed 's/http-php-version:/\n\nhttp-php-version:\n/g' |
sed 's/http-phpmyadmin-dir-traversal:/\n\nhttp-phpmyadmin-dir-traversal:\n/g' | sed 's/http-referer-checker:/\n\nhttp-referer-checker:\n/g' |
sed 's/http-server-header:/\n\nhttp-server-header:\n/g' | sed 's/http-sitemap-generator:/\n\nhttp-sitemap-generator:\n\n/g' |
sed 's/http-slowloris-check:/\n\nhttp-slowloris-check:\n/g' | sed 's/http-stored-xss:/\n\nhttp-stored-xss:\n/g' |
sed 's/http-unsafe-output-escaping:/\n\nhttp-unsafe-output-escaping:\n/g' | sed 's/http-webdav-scan:/\nhttp-webdav-scan:\n/g' |
sed 's/mysql-empty-password:/\n\nmysql-empty-password:\n/g' | sed 's/nbstat:/\n\nnbstat:\n/' |
sed 's/proxy-open-http:/\n\nproxy-open-http:\n/g' | sed 's/rmi-vuln-classloader:/\n\nrmi-vuln-classloader:\n/g' |
sed 's/smtp-strangeport:/\n\nsmtp-strangeport:\n/g' | sed 's/ssl-cert:/\n\nssl-cert:\n/g' |
sed 's/ssh2-enum-algos:/\n\nssh2-enum-algos:/g' | sed 's/ssh-hostkey:/\n\nssh-hostkey:\n/g' |
sed 's/unusual-port:/\n\nunusual-port:\n/g' | sed 's/vmware-version:/\n\nvmware-version:\n/g' | sed 's/vulners:/\n\nvulners:\n/g' |
sed 's/xmlrpc-methods:/\n\nxmlrpc-methods:\n/g' | sed 's/Methods:/Methods: /g' | sed 's/Potentially risky methods:/Potentially Risky: /g' |
sed '/kex_algorithms:/{x;p;x;}' | sed '/server_host_key_algorithms:/{x;p;x;}' | sed '/encryption_algorithms:/{x;p;x;}' |
sed '/mac_algorithms:/{x;p;x;}' | sed '/compression_algorithms:/{x;p;x;}' | sed 's/Service Info:/\n\nService Info:\n/' |
sed 's/fingerprint-strings:/\n\nfingerprint-strings:\n/' | sed '/Nmap done/d' |
sed 's/^[ \t]*//;s/[ \t]*$//' | fmt -s -w 120 | tee $tempdir/nmap_output; echo ''
}

#-------------------------------  CLEAN UP  -------------------------------

f_CLEANUP_FILES(){
[[ -f $tempdir/ac ]] && rm $tempdir/ac; [[ -f $tempdir/arin_nets ]] && rm $tempdir/arin_nets
[[ -f $tempdir/arin_org ]] && rm $tempdir/arin_org; [[ -f $tempdir/asov.json ]] && rm $tempdir/asov.json
[[ -f $tempdir/banners ]] && rm $tempdir/banners; [[ -f $tempdir/bgp.json ]] && rm $tempdir/bgp.json
[[ -f $tempdir/cust ]] && rm $tempdir/cust; [[ -f $tempdir/detected_ports ]] && rm $tempdir/detected_ports
[[ -f $tempdir/fwalk ]] && rm $tempdir/fwalk; [[ -f $tempdir/h3 ]] && rm $tempdir/h3
[[ -f $tempdir/h_issues ]] && rm $tempdir/h_issues; [[ -f $tempdir/dis_issues ]] && rm $tempdir/dis_issues
[[ -f $tempdir/headers ]] && rm $tempdir/headers; [[ -f $tempdir/hoplist ]] && rm $tempdir/hoplist
[[ -f $tempdir/host_ipv4 ]] && rm $tempdir/host_ipv4; [[ -f $tempdir/host_ipv6 ]] && rm $tempdir/host_ipv6
[[ -f $tempdir/inums ]] && rm $tempdir/inums; [[ -f $tempdir/mail2 ]] && rm $tempdir/mail2
[[ -f $tempdir/mail ]] && rm $tempdir/mail; [[ -f $tempdir/mx_hosts ]] && rm $tempdir/mx_hosts
[[ -f $tempdir/mx_ipv4.list ]] && rm $tempdir/mx_ipv4.list; [[ -f $tempdir/mx_ipv6.list ]] && rm $tempdir/mx_ipv6.list
[[ -f $tempdir/mx.list ]] && rm $tempdir/mx.list; [[ -f $tempdir/net_admins ]] && rm $tempdir/net_admins
[[ -f $tempdir/net_orgs ]] && rm $tempdir/net_orgs; [[ -f $tempdir/nets ]] && rm $tempdir/nets
[[ -f $tempdir/nets ]] && rm $tempdir/nets4; [[ -f $tempdir/nets4_raw ]] && rm $tempdir/nets4_raw
[[ -f $tempdir/nets6 ]] && rm $tempdir/nets6; [[ -f $tempdir/nets6_raw ]] && rm $tempdir/nets6_raw
[[ -f $tempdir/nh_list1 ]] && rm $tempdir/nh_list1; [[ -f $tempdir/nh_list2 ]] && rm $tempdir/nh_list2
[[ -f $tempdir/nic_hdls ]] && rm $tempdir/nic_hdls; [[ -f $tempdir/nmap2.v4.txt ]] && rm $tempdir/nmap2.v4.txt
[[ -f $tempdir/nmap2.v6.txt ]] && rm $tempdir/nmap2.v6.txt; [[ -f $tempdir/nmap3.v4.txt ]] && rm $tempdir/nmap3.v4.txt
[[ -f $tempdir/nmap3.v6.txt ]] && rm $tempdir/nmap3.v6.txt; [[ -f $tempdir/nmap_output ]] && rm $tempdir/nmap_output
[[ -f $tempdir/nmap_tmp ]] && $tempdir/nmap_tmp; [[ -f $tempdir/nmap.v4.txt ]] && rm $tempdir/nmap.v4.txt
[[ -f $tempdir/nmap.v6.txt ]] && rm $tempdir/nmap.v6.txt; [[ -f $tempdir/ns4.list ]] && rm $tempdir/ns4.list
[[ -f $tempdir/nse ]] && rm $tempdir/nse; [[ -f $tempdir/ns.list ]] && rm $tempdir/ns.list
[[ -f $tempdir/ns_ipv4.list ]] && $tempdir/ns_ipv4.list; [[ -f $tempdir/ns_ipv6.list ]] && rm $tempdir/ns_ipv6.list
[[ -f $tempdir/org_ids ]] && rm $tempdir/org_ids; [[ -f $tempdir/pfx_lookups ]] && rm $tempdir/pfx_lookups
[[ -f $tempdir/pid ]] && rm $tempdir/pid; [[ -f $tempdir/pocs ]] && rm $tempdir/pocs
[[ -f $tempdir/porg ]] && rm $tempdir/porgs; [[ -f $tempdir/ports ]] && rm $tempdir/ports
[[ -f $tempdir/pov.json ]] && rm $tempdir/pov.json; [[ -f $tempdir/prefixes.list ]] && rm $tempdir/prefixes.list
[[ -f $tempdir/pwhois ]] && rm $tempdir/pwhois; [[ -f $tempdir/pwhois_table ]] && rm $tempdir/pwhois_table
[[ -f $tempdir/rec_ips.list ]] && rm $tempdir/rec_ips.list; [[ -f $tempdir/rec_ips6.list ]] && rm $tempdir/rec_ips6.list
[[ -f $tempdir/rpki.json ]] && rm $tempdir/rpki.json; [[ -f $tempdir/script_args ]] && rm $tempdir/script_args
[[ -f $tempdir/txt_ip.list ]] && rm $tempdir/txt_ip.list; [[ -f $tempdir/txt_ips_tmp ]] && rm $tempdir/txt_ips_tmp
[[ -f $tempdir/whois ]] && rm $tempdir/whois; [[ -f $tempdir/whois2 ]] && rm $tempdir/whois2
[[ -f $tempdir/whois_as ]] && rm $tempdir/whois_as; [[ -f $tempdir/whois_org ]] && rm $tempdir/whois_org
[[ -f $tempdir/whois_temp ]] && rm $tempdir/whois_temp
}

#-------------------------------  ABOUT / HELP  -------------------------------
f_showHELP(){
echo -e "${B}"; f_Long; echo -e "\n ---------------\n  drwho.sh\n ---------------\n"
echo -e "https://github.com/ThomasPWy/drwho.sh,  Author: Thomas Wy,  Version: 4.2 (Mar 2022)"; f_Long ; echo -e "${D}"
echo -e "${G}DEPENDENCIES ${D}"
echo -e "\n${B}Dependencies (essential):${D}\n"
echo "curl, dnsutils (installs dig & host), jq, ipcalc, lynx, nmap, openssl, whois"
echo -e "\n\n${B}Dependencies (recommended):${D}\n"
echo -e "dublin-traceroute, locate/mlocate, mtr, \ntracepath ('iputils-tracepath' in Debian/Ubuntu, 'tracepath' in Termux), whatweb"
echo -e "${B}"; f_Long; echo -e "${G}SOURCES: ${B}APIs${D}\n"
echo -e "${B}Threat Intel${D}\n"
echo -e "GreyNoise (greynoise.io), Project Honeypot (projecthoneypot.org),\nIP Quality Score (ipqualityscore.com), SANS Internet Storm Center (isc.sans.edu),\nStop Forum Spam (stopforumspam.org)"
echo -e "\n${B}ASN, BGP, RPKI, IX & Network Information${D}\n"
echo -e "bgpview.io, Peering DB (peeringdb.com), RIPEstat data API (stat.ripe.net)"
echo -e "\n${B}IP Addr, Host, Domain Information${D}\n"
echo -e "Abusix (abuse contact DNS zone), ip-api.com, RIPEstat, Shodan InternetDB"
echo -e "\n${B}DNS & Subdomains${D}\n"
echo -e "certspotter.com, hackertarget.com: Reverse IP, subdomains, shared name servers, zone transfer in non-connect mode"
echo -e "\n${B}Web Servers & Certificate Transparency${D}\n"
echo -e "hackertarget.com: HTTP headers & WhatWeb (non-connect mode), certspotter.com, urlscan.io"
echo -e "\n\n${G}SOURCES: ${B}DNS Blocklists${D}\n"
echo -e "all.bl.blocklist.de, all.s5h.net, auth.spamrats.com, b.barracudacentral.org,\nbl.spamcop.net, dnsbl.dronebl.org, dnsbl.tornevall.org, ix.dnsbl.manitu.net,\nphishing.rbl.msrbl.net, relays.bl.kundenserver.de, spam.dnsbl.sorbs.net,\ntalosintelligence.com, tor.dan.me.uk, v4.fullbogons.cymru.com, v6.fullbogons.cymru.com\n"
echo -e "\n${G}SOURCES: ${B}Whois${D}\n"
echo -e "whois.cymru.com, whois.pwhois.org, whois.radb.net, RIPEstat,\nRIR whois servers (whois.[afrinic|apnic|arin|ripe].net"
echo -e "Domain registry whois servers are determined automatically by the whois client"
echo -e "\n\n${G}SOURCES: ${B}Software Tools${D}\n"
echo -e "See 'Dependencies'"
echo -e "${B}"; f_Long; echo -e "${G}CUSTOMIZATIONS ${D}\n"
echo -e "\n${B}API KEYS ${D}\n"
echo -e "\nAPI keys are required for usage of Project Honeypot (projecthoneypot.org) and\nIP Quality Score (ipqualityscore.com) APIs"
echo -e "\nAn API key for hackertarget's IP API is recommended (required for the test ping & traceroute APIs)\nQueries are rate-limited without API key. (https://hackertarget.com)"
echo -e "Optained API keys can be entered in the designated fields (script source, line 4)"
echo -e "\n\n${B}EXECUTABLES ${D}\n\nCustom paths to executables of dependencies can be set below the API-key field.\n"
f_Long; echo -e "${G}MAIN MENU HEADER${D}\n"
echo -e "${B}Directory      >${D}  not saving results\n${B}Directory      >${D}  PATH/TO/DIR\n"
echo -e "${B}TargetConnect  >  ${G}true${D}\n${B}TargetConnect  >  ${R}false${D}\n"
echo -e "The ${G}Directory >${D} - field shows the location, any script output is written to."
echo -e "\nTo save script output, chose option s) and enter directory name and path."
echo -e "\nThe ${G}TargetConnect >${D} - field indicates if packets are send from your IP-address to target systems."
echo -e "If set to false, only third party resources are queried."
echo -e "\nUse option ${B}c)${D} to toggle ${B}TARGET - CONNECT ${D} or ${B} NON-CONNECT MODES{D}"; f_Menu
echo -e "${B}"; f_Long; echo -e "  ${G}  OPTIONS\n\n"
echo -e "${B}    x)   General Target Info ${D}\n"
echo -e "         Supported input: AS Numbers, Hostnames, IP Addresses, Networks (CIDR, network names), Org-IDs\n" 
echo -e "\n${B}    o)   Other (Misc. tools not fitting into below categories)${D}\n"
echo -e "${D}         1) Abuse Contact Finder (whois.lacnic.net, other RIRs: RIPEstat)"
echo -e "${D}         2) E-Mail OpenPGP-Key Lookup (DNS: dig)"
echo -e "${D}         3) Reverse Google Analytics Search (hackertarget.com)"
echo -e "${D}         4) MAC Address Vendor Prefix Lookup (Nmap nmap-mac-prefixes file)\n"
echo -e "\n${B}  Information Gathering & Diagnostics:\n"
echo -e "\n${B}    a)   ASNs, BGP, IX\n"
echo -e "${D}         1) Prefix BGP- & RPKI Status"
echo -e "            RIS visibility, ROAs, BGP update activity, RIS-whois consistency, more-/less specifics\n"
echo -e "${D}         2) AS Details"
echo -e "            AS statistics, contact details, IX presence, announced prefixes, peers\n"
echo -e "${D}         4) Internet Exchanges"
echo -e "            IX Contacts & members\n"
echo -e "\n${B}    d)   Domain Reconnaissance${D}\n"
echo -e "${D}         1) Full Domain Recon"
echo -e "            Domain webpresence, DNS records details, domain hosts & MX SSL,"
echo -e "            zone transfer (optional), subdomains, network ranges (via subdomains & network names)"
echo -e "            service provider contacts"
echo -e "            (Sources: cURL, DNS (dig), WhatWeb, whois, APIs: certspotter.io, hackertarget.com, urlscan.io, Ripestat, Shodan)\n"
echo -e "${D}         2) Subdomains & Network Resources Only  (Sources: dig, certspotter.io, hackertarget.com"
echo -e "            Optional: Enumeration of network ranges & service provider contacts\n"
echo -e "${D}         3) Domain Certificate Issuances (certspotter.com)\n"
echo -e "\n${B}  dns)   DNS Records, MX SSL${D}\n"
echo -e "         1) Domain DNS Records Details"
echo -e "            Resource records:"
echo -e "            A, AAAA, MX, NS, SOA, TXT, SRV, NSEC, NSEC3, version.bind"
echo -e "            Diagnostics:"
echo -e "            Best practices (RFC1912), name server response & zone serials, forward confirmed rDNS,"
echo -e "            TCP ping (ports 25,53,80), MX SPAM blocklist check, prefix ROAs, Domain host & MX SSL certificates"
echo -e "            Optional: Shodan data (ports, CPEs & CVEs) and IP reputation check"
echo -e "            (Sources: DNS (dig, host), Nmap scripts, Nping, APIs\n"
echo -e "         2) Domain DNS Records Summary\n"
echo -e "         3) Shared Name Servers"
echo -e "            Lists domains sharing a given name server and"
echo -e "            retrieves additional info about the resolved domain IPs\n"
echo -e "         4) Zone Transfer"
echo -e "         5) dig Batch Mode (Bulk Lookup)"
echo -e "         6) Mail Server/MX Records SSL Info & Cert Dump\n"
echo -e "\n${B}   ip)   IPv4 IP Reputation, Vhosts & CVEs${D}\n"
echo -e "         1) IPv4 Address Threat Enum"
echo -e "            (Sources: DNS, whois, APIs: Abusix, RIPEstat, ip-api.com, threat intel APIs)"
echo -e "         2) Virtual Hosts (hackertarget.com)"
echo -e "         3) DNS Blocklist Fast Check"
echo -e "         4) CVEs (Shodan API)\n"
echo -e "\n${B}    m)   MTU Discovery${D}\n"
echo -e "         1) Nmap: Basic MTU discovery (TCP, UDP)                 (IPv4; privileged mode)"
echo -e "         2) Tracepath: ICMP traceroute & MTU                     (IPv4/IPv6; non-root)\n"
echo -e "\n${B}    n)   Networks${D}\n"
echo -e "         1) Network Report & Whois (various options)             (IPv4/IPv6, public; whois, APIs)"
echo -e "         2) Prefix Address Space / Subnets                       (IPv4/IPv6, public; whois)\n"
echo -e "         3) Ping Sweep                                           (IPv4; private/public; Nmap)"
echo -e "            Custom probes (ARP, ICMP, TCP, UDP, SCTP, raw IP)"
echo -e "         4) Network DNS (rDNS, Vhosts)                           (IPv4; local/public; Nmap, hackertarget.com)"
echo -e "         5) Service Banners / CPEs / CVEs                        (IPv4; APIs: hackertarget.com; Shodan)"
echo -e "         6) Network Hosts Blocklist Check                        (IPv4; public)\n"
echo -e "         7) Duplicate IP Address Detection                       (IPv4; private; Nmap scripts)"
echo -e "            Compares MAC, Netbios server names,"
echo -e "            SSL certificate- & SSH key hashes\n"
echo -e "         8) IoT Devices/Services                                 (IPv4; private; Nmap scripts)"
echo -e "            Bacnet, KNX, Modbus, MQTT, S7\n"
echo -e "         9) LAN Service Discovery"
echo -e "            Broad- & Multicasts (DHCP, DNS, UPNP, Router Solicitation, RIP/OSFP/EIRP)\n"
echo -e "\n${B}    p)   Ping Probes, Port Scan, Firewalk${D}\n"
echo -e "         1) Basic Nmap Scans (Port-, OS/Version- & Script Scans)"
echo -e "         2) Nmap Port Scan (via hackertarget.com IP API)"
echo -e "         3) Nmap: Firewalk, TCP Flag Scans\n"
echo -e "\n${B}    t)   Tracerouting${D}\n"
echo -e "         t1) Tracepath: ICMP Traceroute & MTU Discovery          (IPv4,IPv6)"
echo -e "         t2) MTR: RT-Times, Packet Loss, Jitter                  (IPv4,IPv6)"
echo -e "             MPLS Info (RFC 4950); ICMP, TCP, UDP, ICMP, SCTP"
echo -e "             Supports TCP, UDP, ICMP, SCTP"
echo -e "         t3) MTR: Traceroute using hackertarget.com API          (API key req, IPv4)"
echo -e "         t4) Nmap GeoTrace                                       (IPv4,IPv6)"
echo -e "             Supports TCP, UDP, ICMP & Socket Connect"
echo -e "         t5) Dublin Traceroute: NAT Aware Multipath Traceroute   (ICMP, IPv4)\n"
echo -e "\n${B}    w)   Whois${D}\n"
echo -e "         w1) INVERSE Whois Lookup                                (RIPE, AFRINIC, APNIC, pwhois.org)"
echo -e "         w2) POC Search                                          (RIPE, AFRINIC, APNIC)"
echo -e "         w3) ARIN Object & PoC Search                            (ARIN, pwhois.org)"
echo -e "         w4) Bulk Lookup (pwhois.org)"
echo -e "         w5) DOMAIN Registries Whois Lookup\n"
echo -e "\n${B}  www)   Webservers${D}\n"
echo -e "         1) Web Server Health Check"
echo -e "         2) Website Summary in Non-target-connect Mode (Sources: APIs)"
echo -e "         3) Website Info/Overview"
echo -e "         3) Dump HTTP Headers  (cURL or hackertarget.com API)"
echo -e "         4) Host Cert Dump & SSL Info  (OpenSSL)"
echo -e "${B}"; f_Long; echo -e "${B}x)${G} General Target Info${D}\n\n"
echo -e "Returns data about AS numbers, IP adresses, hostnames\nnetworks (network addresses or -names) and Org-IDs\n\nTarget types are determined automatically.\n\nSearching for organisation names (single words only) may be worth a try if\nthe responsible RIR is unknown, but is less likely to yield the \ndesired results, as RIRs cannot be determined automatically for names.\nOptions w2) & w3) which allow to select a specific RIR \nare better suited for this type of input\n\nOther whois database handles like NIC-Hdls (role-, person objects, etc.),\nARIN net-handles and email addresses are only searchable via options w2) & w3)\n\nNetworks:\nThis option returns general information about public IPv4 & IPv6 networks.\nSelect option n) for specific enumeration tasks and LAN information\n${B}"; f_Long; echo -e "${G}t) Tracerouting Options${D}\n"
echo -e "Optionally return RPKI (ROA) status, geolocation & whois data for each hop.\nInspired by nitefood's fancy asn tool: https://github.com/nitefood/asn"
echo -e "${B}"; f_Long; echo -e "${B}n) ${G}[1] Network Report & Whois${D}\n"
echo -e "Whois data (summary/details), subnets (subdelegations/allocations), related prefixes,\ngeographic distribution, resources with common network name\n(may return false positivies - check country/org/admin-c fields),\nnetwork rDNS & rev.IP, service banners/CPEs/CVEs (API only)"
echo -e "${B}"; f_Long; echo -e "${B}n) ${G}[1] & [3]  Network Ping Sweep ${D}\n"
echo -e "\n${B}DIALOGUE\n"
echo -e "Option   > ${D}  Run Nmap with elevated privileges ${B}[y] | [n]  ?${D}\n"
echo -e "Anyting beyond TCP connect (TCP SYN) packets requires raw socket privileges"
echo -e "\n${B}Options  > ${G}PING SWEEP I  ${D} (in option n) -> 3 only)\n"
echo -e "${B} [1]${D} Public IP address range"
echo -e "${B} [2]${D} Local Network - ARP ping (Nmap default)"
echo -e "${B} [3]${D} Local Network - alternative probes (disable ARP)\n"
echo -e "Choose option 3 to send custom OSI layer 3+ probes within local networks"
echo -e "\n\n${B}PUBLIC NETWORKS\n"
echo -e "\nOptions  > ${G}PING SWEEP II\n"
echo -e "${B} [1]${D} Use Nmap Defaults"
echo -e "${B} [2]${D} Send more probes"; echo -e "${B} [3]${D} Customize options"
echo -e "\nBy default, Nmap sends ICMP echo & timestamp, TCP ACK (443) & TCP SYN (80) probes"
echo -e "\nChoosing option 2 will send the following probes:\n"
echo -e "ICMP echo & timestamp, TCP ACK (80,443,3389),\nTCP SYN (Ports 21,22,25,80,113,443),\nUDP (53,631,40125), SCTP INIT (80,443,5060)"
echo -e "\nIf the ping sweep is run from option 'n) -> 1) Network Report',\nadditional TCP SYN probes will be send to any ports
found via the CPEs & Vulners (Shodan API) option"
echo -e "\n(Reference: https://nmap.org/book/host-discovery.html)\n"
echo -e "${B}"; f_Long; echo -e "${B}[w1]${G} INVERSE Whois Search${D}\n"
echo -e "${B}Syntax for inverse searches:${D}\n\n${G}Object type${D} (e.g. admin-c) and, separated by ${B}semicolon${D}, the ${G}object handle${D} (e.g. JOHNDOE-RIPE).\n\n${G}admin-c;JOHNDOE-RIPE${D}\n\nA successful search for admin-c;JOHNDOE-RIPE should return any resource (networks, orgs...) \nwhere JOHNDOE-RIPE is \nlisted as admin contact.\nInverse search objects have to be unique identifiers (no proper names) of a specified type\ne.g. abuse-c, admin-c, mnt-by, org, tech-c \nNames (role, person or org-name objects) and non-specified nic-hdl objects are not searchable\nSearching by admin-c, mnt-by and org objects is usually most promising"
echo -e "${B}"; f_Long; echo -e "${B}www) ${G}[1] Web Server Health Check${D}\n"
echo -e "\n${B}DEFAULT${D}\n"
echo -e "Website & HTTP Headers:\n"
echo -e "Website overview, server & CMS, link dump, application- & security headers"
echo -e "Very basic information disclosure check: HTTP headers, robots/humans.txt"
echo -e "\nServer instances:\n"
echo -e "Server redirects & response times, RTT (TCP/ICMP),\npage loading times (will be affected by cookie consent banners within EU countries)\nwebsite & certificate hashes, CPEs/CVEs (Shodan), IP reputation, prefix, geolocation"
echo -e "\nSSL/TLS:\n\nCert dump & validation, OCSP, ciphersuites\nVulnerabiliies: Heartbleed, secure renegotiation, Breach, Crime (sources: OpenSSL, testssl.sh)"
echo -e "\n\n${B}ADDITIONAL OPTIONS${D}\n"
echo -e "${B} Options  > ${G} Website, Nmap Scan\n"
echo -e "${B} [1]${D}  Display additional website info"; echo -e "${B} [2]${D}  Nmap Port/Vulners Scan"; echo -e "${B} [3]${D}  BOTH\n"
echo -e "Choosing [1] or [3] will display contact/social media links, \nmeta tags (description, keywords, Open-Graph-Protocol)"
echo -e "Options [2]/[3] allow to choose to run Nmap in either 'safe' or 'intrusive' mode."
echo -e "${B} [1]${D}  Safe Mode - (Uses Nmap Script from category 'safe' only)"
echo -e "${B} [2]${D}  Intrusive Mode  (using 'safe' & 'intrusive' skripts, skipping overly time consuming script scans)"
echo -e "${B} [3]${D}  Intrusive Mode - SLOW"
echo -e "${B} [4]${D}  Intrusive Mode - SLOW, all TCP Ports"
echo -e "\nDepending on the results of the OS & service version scans, both safe & intrusive mode\nwill display potential CVEs\n"
echo -e "Service version scans require elevated privileges. While this renders the 'safe' mode option\neffectively useless for non-privileged users, most scripts from the intrusive options will\nalso work in unprivileged mode."
echo -e "\nChoosing intrusive mode will enumerate SSH algos and check for:\n\nAdditional information disclosure vulnerabilities by scraping for interesting directories and HTML commentaries\n, potentially risky HTTP methods like put & delete,\nremote file inclusion vulnerabilities, unprotected MySQL root accounts (empty root password) and\nanonymous FTP logins. It will also run basic non-targeted XSS and CSRF checks"
echo -e "(Sources:  cURL, Lynx, Nmap scripts, Nping, ping, testssl.sh, WhatWeb, APIs\n"
echo -e "${B}"; f_Long; echo -e "\n${G}NMAP SCRIPTS${D}\n"
echo -e "\nScripts depending on Nmap's version/OS detection (e.g. vulners.nse, unsusual.nse) and\ntraceroute features (e.g. path-mtu.nse) require raw socket privileges\n and must therefore be run with elevated/root privileges"
echo -e "\n\n${B}DNS Records${D}\n"
echo -e "dns-check-zone.nse, dns-srv-enum.nse, fcrdns.nse"
echo -e "\n\n${B}Local Network Discovery${D}"
echo -e "\nService Discovery Broadcasts:\n"
echo -e "broadcast-dhcp-discover.nse, broadcast-dns-service-discovery.nse,\nbroadcast-upnp-info.nse, broadcast-igmp-discovery.nse,\nbroadcast-ospf2-discover.nse, broadcast-rip-discover.nse"
echo -e "\nDuplicate Address Detection:\n"
echo -e "duplicates.nse, nbstat.nse, ssl-cert.nse, ssh-hostkey.nse"
echo -e "\nIoT Devices:\n"
echo -e "bacnet-info.nse, knx-gateway-discover.nse, modbus-discover.nse,\nmqtt-subscribe.nse, s7-info.ns"
echo -e "\n\n${B}MTU Discovery, Traceroute${D}\n"
echo -e "path-mtu.nse, traceroute-geolocation.nse"
echo -e "\n\n${B}Port Scanning Options${D}\n"
echo -e "banner.nse, firewalk.nse, https-redirect.nse, ssl-cert.nse, unusual-port.nse,\nvulners.nse, various default scripts"
echo -e "\n\n${B}Web Servers${D}"
echo -e "\nSafe:\n\nhttp-apache-server-status.nse, http-cookie-flags.nse, http-php-version.nse,\nhttp-mobileversion-checker.nse, http-affiliate-id.nse, http-referer-checker.nse,\nssh-hostkey.nse, unusual-port.nse, vulners.nse"
echo -e "\nIntrusive:\n\nftp-anon.nse, http-auth.nse, http-auth-finder.nse, http-aspnet-debug.nse,\nhttp-cors.nse, http-csrf.nse, http-dombased-xss.nse, http-enum.nse, \nhttp-malware-host.nse, http-methods.nse, http-phpmyadmin-dir-traversal.nse,\nhttp-slowloris-check.nse, http-stored-xss, http-unsafe-output-escaping,nse,\nhttp-webdav-scan.nse, mysql-empty-password.nse, xmlrpc-methods.nse,\nrmi-vuln-classloader.nse, ssh2-enum-algos.nse"
echo -e "\nIntrusive (slow):\n\nhttp-backup-finder.nse, http-jsonp-detection.nse, http-open-proxy.nse,\nsmtp-strangeport.nse, rpcinfo.nse, vmware-version.nse"
f_Menu
}

#-------------------------------  SUBMENUS  -------------------------------

f_optionsBGP(){
echo -e "   ${B}Options  > ${G}BGP PREFIXES / ASNS / INTERNET EXCHANGES ${D}\n"
echo -e "   ${B}[1]${D}  Prefix ${bold}BGP, RPKI${D} Status"
echo -e "   ${B}[2]${D}  AS ${bold}Details${D}"
echo -e "   ${B}[3]${D}  AS ${bold}Announcements${D} (Prefixes)"
echo -e "   ${B}[4]${D}  ${bold}IX${D} Info"
echo -e "\n   ${B}[b]${D}  Back to the Global ${G}Options Menu${D}"
}
f_optionsDNS(){
echo -e "   ${B}Options  > ${G}DNS ${D}\n"
echo -e "   ${B}[1]${D}  Domain DNS Records ${bold}Details${D}"
echo -e "   ${B}[2]${D}  Domain DNS Records ${bold}Summary${D}"
echo -e "   ${B}[3]${D}  ${bold}Shared ${D}Name Servers"
echo -e "   ${B}[4]${D}  Zone ${bold}Transfer${D}"
echo -e "   ${B}[5]${D}  dig ${bold}Batch Mode${D} (Mass DNS Lookup)"
echo -e "   ${B}[6]${D}  MX Record / Mail Server ${bold}SSL${D}"
echo -e "\n   ${B}[b]${D}  Back to the Global ${G}Options Menu${D}"
}
f_optionsDOMAIN(){
echo -e "   ${B}Options  > ${G}DOMAIN RECONNAISSANCE ${D}\n"
echo -e "   ${B}[1]${D}  ${bold}Full Domain Recon${D}"
echo -e "   ${B}[2]${D}  Subdomains & Network Resources Only"
echo -e "   ${B}[3]${D}  Domain Certificate Issuances"
echo -e "\n   ${B}[b]${D}  Back to the Global ${G}Options Menu${D}"
}
f_optionsHOSTS(){
echo -e "\n   ${B}Options  > ${G}IPv4 ADDR INFORMATION\n"
echo -e "   ${B}[1]${D}  IPv4 Address Reputation"
echo -e "   ${B}[2]${D}  Virtual Hosts"
echo -e "   ${B}[3]${D}  Blocklist Fast Check"
echo -e "   ${B}[4]${D}  CVE Fast Check"
echo -e "\n   ${B}[b]${D}  Back to the Global ${G}Options Menu${D}"
}
f_optionsMTU() {
echo -e "\n  ${B}Options  > MTU DISCOVERY ${D}$denied \n"
echo -e "  ${B}[m1]${G}  NMAP     ${D}   Basic MTU discovery (TCP,UDP) ${B}IPv4"
echo -e "  ${B}[m2]${G}  Tracepath${D}   Traceroute & MTU Discovery (ICMP, non-root)"
echo -e "\n   ${B}[b]${D}  Back to the Global Options ${G}Menu${D}"
}
f_optionsNET(){
echo -e "\n   ${B}Options  > ${G}NETWORKS\n"
echo -e "   ${B}[1]${D}  Network Report & Whois          ${B}(IPv4, IPv6)${D}"
echo -e "   ${B}[2]${D}  Prefix Address Space / Subnets  ${B}(RIPE, AFRINIC & APNIC)"
echo -e "   ${B}[3]${D}  Ping Sweep                      ${B}(IPv4, local/public) ${R}$denied"
echo -e "   ${B}[4]${D}  Network DNS (rDNS, Vhosts)      ${B}(IPv4, local/public)"
echo -e "   ${B}[5]${D}  Service Banners                 ${B}(IPv4)"
echo -e "   ${B}[6]${D}  Network Hosts Blocklist Check   ${B}(IPv4)\n"
echo -e "   ${B}[7]${D}  Duplicate IP Address Detection  ${B}(IPv4, local)"
echo -e "   ${B}[8]${D}  IoT Devices/Services            ${B}(IPv4, local)"
echo -e "   ${B}[9]${D}  LAN Service Discovery ${D}"
echo -e "        Broad- & Multicasts (DHCP, Routing, IGMP, UPNP, DNS)\n"
echo -e "\n   ${B}[b]${D}  Back to the Global ${G}Options Menu${D}"
}
f_optionsNETDNS1(){
echo -e "${B} [1] ${G}Nmap${B}  >${D}  Reverse DNS (Name servers: 1.1.1.1, 9.9.9.9)"
echo -e "${B} [2] ${G}Nmap${B}  >${D}  Reverse DNS (Custom name servers) $denied"
[[ $option_enum = "4" ]] && echo -e "\n${R} [0]${D} SKIP/CANCEL" || echo -e "\n${R} [0]${D} SKIP"
}
f_optionsNETDNS2(){
echo -e "${B} [1] ${G}API${B}   >${D}  Reverse IP  (hackertarget.com API max. size: /24)"
echo -e "${B} [2] ${G}Nmap${B}  >${D}  Look up IPv6 addresses for PTR records / reverse IP"
echo -e "\n${B} [3]${D} BOTH"; [[ $option_enum = "4" ]] && echo -e "${R} [0]${D} SKIP/CANCEL" || echo -e "${R} [0]${D} SKIP"
}
f_options_P(){
echo -e "\n  ${B}Options  > ${G}NMAP PORT SCANS${D}\n"
echo -e "  ${B}[p1]${G}   NMAP${D}   ${bold}Port-, OS/Version- & Vulnerability Scans${D} ${R}$denied"
echo -e "  ${B}[p2]${G}   API${D}    ${bold}Port Scan${D}  (hackertarget.com API) ${B}IPv4"
echo -e "  ${B}[p3]${G}   NMAP${D}   ${bold}Firewalk, TCP Flag Scans ${D}${R}$denied"
echo -e "\n   ${B}[b]${D}   Back to the Global Options ${G}Menu${D}"
}
f_optionsTOOLS(){
echo -e "\n   ${B}Options  > ${G}TOOLS\n"
echo -e "   ${B}[1]${D}  Abuse Contact Finder"
echo -e "   ${B}[2]${D}  E-Mail OpenPGP-Key Lookup (DNS)"
echo -e "   ${B}[3]${D}  Reverse Google Analytics Search"
echo -e "   ${B}[4]${D}  MAC Address Vendor Prefix Lookup"
echo -e "   ${B}[5]${D}  Network Interfaces & Local System Information"
echo -e "\n   ${B}[b]${D}  Back to the Global ${G}Options Menu${D}"
}
f_options_T() {
echo -e "\n   ${B}Options  > ${G}TRACEROUTE${D}\n"
echo -e "   ${B}[t1]${G}  Tracepath${D}          traceroute & MTUs, non-root   ${R}$denied"
echo -e "   ${B}[t2]${G}  MTR${D}                RT-Times, Packet Loss, Jitter; TCP,UDP,ICMP ${R}$denied"
echo -e "   ${B}[t3]${G}  API${D}                MTR via hackertarget.com           ${B}(IPv4)"
echo -e "   ${B}[t4]${G}  Nmap${D}               TCP Traceroute & MaxMind Geolocation Data  ${R}$denied"
echo -e "   ${B}[t5]${G}  Dublin Traceroute${D}  NAT-aware, Multipath Tracerouting  ${B}(IPv4)  ${R}$denied"
echo -e "\n   ${B}[b]${D}    Back to the Global Options ${G}Menu${D}\n"
}
f_optionsWHOIS(){
echo -e "\n   ${B}Options  > ${G}WHOIS ${D}\n"
echo -e "   ${B}[w1]${D}  ${bold}INVERSE${D} Whois                    ${B}(RIPE,AFRINIC,APNIC)"
echo -e "   ${B}[w2]${D}  ${bold}PoCs ${D}                            ${B}(RIPE,AFRINIC,APNIC)"
echo -e "   ${B}[w3]${D}  ${bold}Net Handles/ ORGs / PoCs${D}         ${B}(ARIN)"
echo -e "   ${B}[w4]${D}  ${bold}Netw/IP Address & AS Bulk ${D}Lookup ${B}(whois.cymru.com, whois.pwhois.org)"
echo -e "   ${B}[w5]${D}  ${bold}Domain${D} Whois Lookup"
echo -e "\n   ${B}[b]${D}  Back to the Global ${G}Options Menu${D}"
}
f_optionsWWW(){
echo -e "\n   ${B}Options  > ${G}WEB SERVERS\n"
echo -e "   ${B}[1]${D}  Server ${bold}Health Check  ${R}$denied ${D}"
echo -e "   ${B}[2]${G}  API${D} Website Overview  (WhatWeb via hackertarget.com / urlscan.io)"
echo -e "   ${B}[3]${G}  API/cURL${D} Dump HTTP Headers"
echo -e "   ${B}[4]${G}  OpenSSL${D}  Host Cert Dump & SSL Info"
echo -e "\n   ${B}[b]${D}  Back to the Global Options ${G}Menu${D}"
}

#-------------------------------  MAIN PROGRAM LOOP  -------------------------------

echo -e " ${B}
  ____                _           
 |  _ \ _ ____      _| |__   ___  
 | | | | '__\ \ /\ / / '_ \ / _ \ 
 | |_| | |   \ V  V /| | | | (_) |
 |____/|_|    \_/\_/ |_| |_|\___/ 
 ${D}"
echo -e "\033[3;39m  \"whois the Doctor? Who? Dr Who?\" ${D}"
option_connect="1"; echo ''; f_Menu
while true
do
echo -e -n "\n    ${B}?${D}    " ; read choice
if [ $option_connect = "0" ] ; then
denied=" (target-connect-mode only)" ; else
denied='' ; fi; out="$tempdir/out"; file_date=$(date -I)
case $choice in
b) echo ''; f_Menu ;;
cc|clear) clear; f_Menu ;;
#************** TOGGLE CONNECT/NON-CONNECT-MODES *******************
c|con|connect) echo '' ; f_Long; f_targetCONNECT; echo ''; f_Menu ;;
#************** ADD Permanent Folder  *******************
s | r) f_makeNewDir; f_Long; f_REPORT; echo ''; f_targetCONNECT; f_Menu ;;
x)
f_makeNewDir; f_Long; unset rir; unset target_type
echo -e "\n${B}TARGET INFO >${G} Expected input:${D}${bold} ASN, IP Addr, CIDR, Org-ID or Network Name${D}\n"
echo -e -n "\n${B}Options  >  [1]${D} Set target ${B}| [2]${D} Target list ${B}| [b]${D} Back to the ${B}main menu ?${D}  " ; read option_target
if [ $option_target = "1" ] || [ $option_target = "2" ]; then
option_detail="1"; domain_enum="false"; bgp_details="false"; option_netdetails2="0"; option_netdetails5="0"; threat_enum="false"
file_date=$(date -I); f_get_IX_PFX; if [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target  >  ${G}PATH TO FILE  ${B}>>${D} " ; read input
cat $input > $tempdir/targets_raw; else
echo -e -n "\n${G}TARGET  ${B}>>${D}  " ; read input
echo $input | sed 's/\,/\n/g' | sed 's/;/\n/g' > $tempdir/targets_raw; fi
f_prepareINPUT "$tempdir/targets_raw" > $tempdir/targets.list
for t in $(tr [:upper:] [:lower:] < $tempdir/targets.list); do 
object_hostn=$(echo "$t" | cut -d '@' -f 2- | cut -d '/' -f -1 | grep -sEoa "$REGEX_HOSTNAME")
object_other=$(echo $t | grep -sEa -v "\.|:|/|@"); no_dash=$(echo $t | cut -s -d '-' -f 1 | tr -d ' ')
no_slash=$(echo $t | cut -s -d '/' -f 1 | tr -d ' ')
if [ -n "$object_other" ]; then
target_asn=$(echo $t | tr -d ' ' | sed 's/asn//' | sed 's/as-//' | sed 's/as//' | grep -v '[a-z]' | grep -sEo "[0-9]{1,11}")
[[ -n "$target_asn" ]] && echo $target_asn >> $tempdir/asns || echo $t >> $tempdir/other
elif [ -n "$object_hostn" ]; then
echo "$object_hostn" >> $tempdir/host_names
elif [ -n "$no_slash" ] || [ -n "$no_dash" ]; then
[[ $no_slash =~ $REGEX_IP4 ]] || [[ $no_dash =~ $REGEX_IP4 ]] && echo $t >> $tempdir/netsv4
[[ $no_slash =~ $REGEX_IP6 ]] || [[ $no_dash =~ $REGEX_IP6 ]] && echo $t >> $tempdir/netsv6; else
[[ $t =~ $REGEX_IP4 ]] && echo $t >> $tempdir/ipv4; [[ $t =~ $REGEX_IP6 ]] && echo $t >> $tempdir/ipv6; fi; done
#************** ASNs **************
if [ -f $tempdir/asns ]; then
target_type="as"; out="${outdir}/ASN_SUMS.file_date.txt"
input_sorted=$(cat $tempdir/asns | tr -d 'as' | tr -d 'AS' | tr -d ' ' | sort -ug)
f_printTARGET_TYPE "AS NUMBERS"; for x in $input_sorted; do
echo ''; f_AS_SHORT "$x"; f_CLEANUP_FILES; unset x; unset as_rir; done | tee -a ${out}; unset target_type; unset input_sorted; rm $tempdir/asns; fi
#************** Hostnames **************
if [ -f $tempdir/host_names ]; then
out="${outdir}/HOSTNAMES.${file_date}.txt"; target_type="hostname"; input_sorted=$(sort -u $tempdir/host_names)
f_printTARGET_TYPE "HOST NAMES"; for x in $input_sorted; do
f_CLEANUP_FILES; unset hostv4; unset hostv6; echo ''; f_Long; echo ''; f_dnsCHAIN "$x"; done | tee -a ${out}
if [ -f $tempdir/x4 ] || [ -f $tempdir/x6 ]; then
echo '' | tee -a ${out}; f_HEADLINE2 "TARGET IP ADDRESSES" | tee -a ${out}
[[ -f $tempdir/x4 ]] && echo '' && f_printADDR "$(cat $tempdir/x4)" | tee -a ${out}
[[ -f $tempdir/x6 ]] && echo '' && f_printADDR "$(cat $tempdir/x6)" | tee -a ${out}; fi; unset target_type; unset input_sorted; fi
#************** IPv4 Addresses **************
if [ -f $tempdir/ipv4 ]; then
target_type="default"; input_sorted=$(f_EXTRACT_IP4 "$tempdir/ipv4"); f_printTARGET_TYPE "IPV4 ADDRESSES"
out="${outdir}/IPv4_HOSTS.${file_date}.txt"; target_type="default"
for x in $input_sorted; do
echo ''; f_CLEANUP_FILES; f_HOST_DEFAULT "$x"; unset x; unset rir; done | tee -a ${out}; unset target_type; unset input_sorted; rm $tempdir/ipv4; fi
#************** IPv6 Addresses **************
if [ -f $tempdir/ipv6 ]; then
input_sorted=$(sort -u $tempdir/ipv6); f_printTARGET_TYPE "IPV6 ADDRESSES"
out="${outdir}/IPv6_HOSTS.${file_date}.txt"; target_type="default"; for x in $input_sorted; do
echo ''; f_CLEANUP_FILES; f_HOST_DEFAULT "$x"; unset x; unset rir; done | tee -a ${out}; unset target_type; unset input_sorted; rm $tempdir/ipv6; fi
#************** IPv4 Networks **************
if [ -f $tempdir/netsv4 ]; then
out="${outdir}/NETWORKS.${file_date}.txt"; target_type="net"
input_sorted=$(sort -u $tempdir/netsv4 | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n); f_printTARGET_TYPE "IPV4 NETWORKS"
for x in $input_sorted; do
f_CLEANUP_FILES; echo ''; is_net=$(echo $x cut -s -d '/' -f -1)
[[ -n "$is_net" ]] && net_ip=$(echo $x | cut -d '/' -f 1 | tr -d ' ') || net_ip=$(echo $x | cut -d '-' -f 1 | tr -d ' ')
f_BOGON "$net_ip"; if [ $bogon = "TRUE" ]; then
f_BOGON_HEADER "$x"; echo ''; ipcalc -b -n $x | grep -E "Address:|Netmask:|Wildcard:|HostMax|^Hosts/Net:"; else
f_WHOIS_NET "$x"; unset x; unset rir; fi; done | tee -a ${out}; unset target_type; unset input_sorted; rm $tempdir/netsv4; fi
#************** IPv6 Networks **************
if [ -f $tempdir/netsv6 ]; then
out="${outdir}/NETWORKS.${file_date}.txt"; target_type="net"; input_sorted=$(sort -u $tempdir/netsv6)
f_printTARGET_TYPE "IPV6 NETWORKS"; for x in $input_sorted; do
f_CLEANUP_FILES; echo ''; is_net=$(echo $x cut -s -d '/' -f -1)
[[ -n "$is_net" ]] && net_ip=$(echo $x | cut -d '/' -f 1 | tr -d ' ') || net_ip=$(echo $x | cut -d '-' -f 1 | tr -d ' ')
f_BOGON "$net_ip"; [[ $bogon = "TRUE" ]] && f_BOGON_HEADER "$x" || f_whoisNET "$x"
unset x; unset rir; done | tee -a ${out}; unset target_type; unset input_sorted; rm $tempdir/netsv6; fi
#************** Org-IDs / Network Names **************
if [ -f $tempdir/other ]; then
out="${outdir}/TARGETS_OTHER.${file_date}.txt"; target_type="net"; input_sorted=$(sort -u $tempdir/other)
f_printTARGET_TYPE "NETWORK/ORG  NAME/ID"
for x in $input_sorted; do
f_CLEANUP_FILES; out="${outdir}/$x.txt"; echo ''; f_HEADLINE "$x"
echo -e "Searching pwhois.org by org-id ...\n"
whois -h whois.pwhois.org registry org-id=$x | grep ':' > $tempdir/pwhois_id
if [[ $(grep -c ':' $tempdir/pwhois_id) -gt 4 ]]; then
[[ -f $tempdir/pwhois_id ]] && f_printPWHOIS_ORG "$tempdir/pwhois_id" > $tempdir/pid; else
echo -e "No results\n"; fi
echo -e "Searching pwhois.org by org-name ...\n"
whois -h whois.pwhois.org registry org-name=$x | grep ':' > $tempdir/pwhois_org
if [[ $(grep -c ':' $tempdir/pwhois_id) -gt 4 ]]; then
[[ -f $tempdir/pwhois_id ]] && f_printPWHOIS_ORG "$tempdir/pwhois_org" > $tempdir/porg; else
echo -e "No results\n"; fi
[[ -f $tempdir/pid ]] && f_HEADLINE2 "$x (pwhois.org ID Search)\n" | tee -a ${out} && cat $tempdir/pid | tee -a ${out}
[[ -f $tempdir/porg ]] && f_HEADLINE2 "$x (pwhois.org Name Search)\n" | tee -a ${out} && cat $tempdir/porg | tee -a ${out} && echo '' && f_Long
echo -e "\nSearching RIR databases ..."
whois -h whois.ripe.net -- "--no-personal -a $x" | sed 's/-GRS//' | sed 's/# Filtered//' > $tempdir/whois_all
org_count=$(grep -sEac "^org-name:" $tempdir/whois_all); orgid_count=$(grep -sEac "^org:" $tempdir/whois_all)
net_count=$(grep -Ec "^inet[6]?num:" $tempdir/whois_all); net4_count=$(grep -sEac "^inetnum:" $tempdir/whois_all)
net6_count=$(grep -sEac "^inet6num:" $tempdir/whois_all); admins_sorted=$(grep -sEa "^admin-c:" $tempdir/whois_all | sort -u)
admin_count=$(f_countW "$admins_sorted")
if [[ $orgid_count -gt 0 ]]; then
sed -e '/./{H;$!d;}' -e 'x;/org:/!d' $tempdir/whois_all | grep -sEa "^org:|^organisation:|^source:" | sed '/org:/i nnn' |
sed '/organisation:/i nnn' | sed '/source:/i ;' | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' |
sed 's/nnn/\n/g' | tr -d ' ' | sort -u > $tempdir/orgids
if [ -f $tempdir/orgids ]; then
f_HEADLINE2 "ORGIDs" | tee -a ${out}
sed 's/;/  ->  /g' $tempdir/orgids  | sed G | tee -a ${out}; fi
arin_orgs=$(grep 'ARIN' $tempdir/orgids | cut -s -d ';' -f 1 | tr -d ' ' | grep -v 'ARIN' | sort -u)
if [ -n "$arin_orgs" ]; then
for o in $arin_orgs; do
whois -h whois.arin.net o - $o | grep -v '#' | grep '(' | sort -u; done > $tempdir/arin_orgs; fi 
orgnames=$(grep -sEa "^org-name:" $tempdir/whois_all | awk '{print $NF}' | tr -d ' ')
if [ -n "$orgnames" ]; then
sed -e '/./{H;$!d;}' -e 'x;/org-name:/!d' $tempdir/whois_all > $tempdir/org_results
oids=$(grep -v 'ARIN' $tempdir/orgids | cut -s -d ';' -f 1 | tr -d ' ' | sort -u)
for o in $oids; do
grep -m 1 -A 10 -sEaw "$o" $tempdir/org_results > $tempdir/org_tmp; echo ''; f_ORG_SHORT "$tempdir/org_tmp"; done > $tempdir/orgs; fi
if [[ -f $tempdir/arin_orgs ]] || [[ -f $tempdir/orgs ]]; then
f_HEADLINE2 "ORGS  (SOURCE: RIR WHOIS SERVERS)\n" | tee -a ${out}
[[ -f $tempdir/arin_orgs ]] && echo '' | tee -a ${out} && sort -u $tempdir/arin_orgs | sed G | tee -a ${out}
[[ -f $tempdir/orgs ]] && cat $tempdir/orgs | tee -a ${out}; fi; fi
if [[ $admin_count -gt 0 ]]; then
sed -e '/./{H;$!d;}' -e 'x;/admin-c:/!d' $tempdir/whois_all | grep -sEa "^admin-c:|^source:" | sed '/admin-c:/i nnn' |
sed '/source:/i ;' | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' |
sed 's/nnn/\n/g' | tr -d ' ' | sort -u > $tempdir/admins
if [ -f $tempdir/admins ]; then
f_HEADLINE2 "ADMINS" | tee -a ${out}
sed 's/;/  ->  /g' $tempdir/admins  | sed G | tee -a ${out}; fi
if [[ $admin_count -lt 9 ]]; then
f_Long  | tee -a ${out}; echo ''  | tee -a ${out}
for ad in $(cat $tempdir/admins); do
rir=$(echo "$ad" | cut -d ';' -f 2 | tr -d ' ')
adm=$(echo "$ad" | cut -d ';' -f 1 | tr -d ' ')
f_ADMIN_C "$adm"; unset rir; unset adm; done  | tee -a ${out}; fi; fi
if [[ $net_count -gt 0 ]]; then
net_headline=$(f_HEADLINE2 "NETWORKS\n\nIPv4: $net4_count; IPv6: $net6_count; TOTAL: $net_count)\n\n")
f_getNETS "$tempdir/whois_all" > $tempdir/nets_tmp
grep -E "^inet[6]?num:|^netname:|^descr:|^country:|^org:|^admin-c:|^abuse-c:|^source:" $tempdir/nets_tmp | sed '/DUMY-RIPE/d' |
sed '/inetnum:/{x;p;x;}' | sed '/inet6num:/{x;p;x;}' > $tempdir/net_resources; echo -e "$net_headline" | tee -a ${out}
[[ $net6_count -gt 20 ]] && echo -e "IPv6 Networks: See ${outdir}/NET_RANGES_$x.txt\n" | tee -a ${out}
if  [[ $net4_count -gt 0 ]]; then
f_getNETS4 "$tempdir/net_resources" > $tempdir/resources_v4
if [[ $net4_count -lt 61 ]]; then
nets4=$(grep -sEa "^inetnum:" $tempdir/whois_all | awk '{print $2 $3 $4}' | sort -u)
f_DEAGGREGATE "$nets4" >> $tempdir/resources_v4; cat $tempdir/resources_v4 | tee -a ${out}; else
echo -e "IPv4 Networks: See ${outdir}/NET_RANGES_$x.txt\n" | tee -a ${out}; fi; fi 
if [[ $net6_count -gt 0 ]]; then
[[ $net4_count -gt 0 ]] && f_Long > $tempdir/resources_v6; f_getNETS6 "$tempdir/net_resources" >> $tempdir/resources_v6
echo '' >> $tempdir/resources_v6
if [[ $net6_count -lt 21 ]]; then
cat $tempdir/resources_v6 | tee -a ${out}
if [[ $net6_count -gt 3 ]]; then
f_Medium | tee -a ${out}; grep -E "^inet6num:" $tempdir/nets_tmp | awk '{print $2 $3 $4}' | sort -u |
sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' | sed 's/ /  /g' | fmt -50 | tee -a ${out}; fi; fi; fi
echo -e "$net_headline" > ${outdir}/NET_RANGES_$x.txt; [[ -f $tempdir/resources_v4 ]] && cat $tempdir/resources_v4 >> ${outdir}/NET_RANGES_$x.txt
[[ -f $tempdir/resources_v6 ]] && cat $tempdir/resources_v6 >> ${outdir}/NET_RANGES_$x.txt; fi
done; rm $tempdir/other; unset x; unset target_type; unset input_sorted; fi; unset rir; unset x; unset target_type; unset target_asn
unset option_type; unset object_other; unset stripped; unset net_ip; echo ''; fi; f_removeDir; f_Menu
;;
#************** MISC OPTIONS **************
o)
f_makeNewDir; f_Long; domain_enum="false"; target_type="other"; f_optionsTOOLS; echo -e -n "\n${B}    ?${D}   " ; read option_tools
if [ $option_tools != "b" ]; then
[[ $option_tools = "1" ]] && echo -e "${B}\nABUSE CONTACT FINDER > ${G} INPUT:${D}${bold} ASN, IP Addr, Network Addr (CIDR)${D}\n"
[[ $option_tools = "2" ]] && echo -e "${B}\nDNS OPENPGP-KEY LOOKUP > ${G} INPUT: ${D}${bold} Email Address${D}\n"
[[ $option_tools = "3" ]] && echo -e "${B}\nRev. Google Analytics Search > ${G} INPUT:${D}${bold} Google analytics ID ${D} e.g. UA-123456\n"
if [ $option_tools = "5" ]; then
out="${outdir}/LOCAL_SYSTEM.txt"; target_type="nic"; bgp_details="false"
nic4=$(ip -4 -br addr show up scope global | grep 'UP' | cut -d ' ' -f 1 | tr -d ' ' | sort -u)
mem=$(free --mega | grep 'Mem:' | awk '{print "Total:",$2,"| Used:",$3,"| Free:",$4,"| Avail.:",$NF}')
echo'' | tee -a ${out}; f_Long | tee -a ${out}
echo "[+] LOCAL SYSTEM SUMMARY | $(date -R)" | tee -a ${out} ; f_Long | tee -a ${out}
echo -e "\nUSER & MACHINE\n" | tee -a ${out}; echo -e "\nUser:             $(whoami)" | tee -a ${out}
echo -e "\nGroups:           $(groups)" | tee -a ${out}; echo -e "\nMachine:          $(uname -n)  ($(uname -o))" | tee -a ${out}
echo -e "\nKernel:           $(uname -r)" | tee -a ${out}; echo -e "\nUptime:          $(uptime)" | tee -a ${out}
echo -e "\nMemory:           $mem\n\n" | tee -a ${out}
if ! [[ $(uname -o) =~ "Android" ]]; then
f_Long | tee -a ${out}; echo -e "\nDEFAULT NAME SERVERS\n" | tee -a ${out}; f_getSYSTEM_DNS | tee -a ${out}; fi
f_IFLIST | tee -a ${out}; f_Long | tee -a ${out}; echo -e "\nPUBLIC IP ADDRESSES\n" | tee -a ${out}
for i4 in $nic4; do
echo -e "\nPublic IPv4:      $(curl -s -m 7 --interface $i4 https://api.ipify.org?format=json | jq -r '.ip')  ($i4)\n"; done > $tempdir/pub4
cat $tempdir/pub4 | tee -a ${out}; pub4=$(f_EXTRACT_IP4 "$tempdir/pub4")
addr_v6=$(ip -br addr show up scope global | grep 'UP' | grep -Eo "$REGEX_IP6")
for addr in $addr_v6; do
f_BOGON "$addr"; [[ $bogon = "TRUE" ]] || echo $addr >> $tempdir/pub6; done
pub6=$(sort -u $tempdir/pub6)
if [ -n "$pub4" ] || [ -n "$pub6" ]; then
for a in $pub4; do
curl -s -m 5 http://ip-api.com/json/${a}?fields=91137 > $tempdir/geo.json; geo=$(jq -r '.country' $tempdir/geo.json)
f_getABUSE_C "$a"; abuse=$(cat $tempdir/abx | tr '[:space:]' ' ')
mobile=$(jq -r '.mobile' $tempdir/geo.json | grep -o 'true' | sed 's/true/| MOBILE/')
echo -e "\n\n>  $a\n"
echo -e "   $geo | $(jq -r '.org' $tempdir/geo.json) | $abuse | $(f_TOR "${a}") $mobile\n"
f_ROUTE "$a"; done | tee -a ${out}
for z in $pub6; do
curl -s -m 5 http://ip-api.com/json/${z}?fields=91137 > $tempdir/geo.json; geo=$(jq -r '.country' $tempdir/geo.json)
f_getABUSE_C "${z}"; abuse=$(cat $tempdir/abx | tr '[:space:]' ' ')
mobile=$(jq -r '.mobile' $tempdir/geo.json | grep -o 'true' | sed 's/true/| MOBILE/')
echo -e "\n\n>  $z\n"; echo -e "   $geo | $(jq -r '.org' $tempdir/geo.json) | $abuse $mobile\n"
f_ROUTE "$z"; done | tee -a ${out}; fi; else 
echo ''; f_setTARGET; if [ $option_tools = "1" ]; then
out="${outdir}ABUSE_CONTACTS.${file_date}.txt"; echo '' | tee -a ${out}; f_HEADLINE2 "ABUSE CONTACTS  ($file_date)\n" | tee -a ${out}
elif [ $option_tools = "2" ]; then
out="${outdir}/OPENPGPKEYS.${file_date}.txt"; echo '' | tee -a ${out}
f_HEADLINE2 "DNS OPENPGP KEY LOOKUP  ($file_date)" | tee -a ${out}
elif [ $option_tools = "3" ]; then
out="${outdir}/REV_GOOGLE_ANALYTICS.txt"; echo '' | tee -a ${out}; f_HEADLINE2 "REVERSE GOOGLE ANALYTICS ($file_date)\n" | tee -a ${out}
elif [ $option_tools = "4" ]; then
out="${outdir}/MAC_ADDR_VENDORS.txt"; path_nmap_mac_pfx=$(locate nmap-mac-prefixes)
echo '' | tee -a ${out}; f_HEADLINE2 "MAC ADDRESS VENDOR LOOKUP ($file_date)" | tee -a ${out}; fi
for x in $(cat $tempdir/targets.list); do
f_CLEANUP_FILES; if [ $option_tools = "1" ]; then
f_abuse_cFINDER "$x"
elif [ $option_tools = "2" ]; then
mail1=$(echo $x | cut -d "@" -f 1); mail2=$(echo $x | cut -d "@" -f 2)
digest=$(echo -n $mail1 | openssl dgst -sha256 | cut -d "=" -f 2 | cut -c 1-57)
echo -e "\n\n$x\n"; opgp_key=$(dig @1.1.1.1 +short +vc type61 ${digest}._openpgpkey.${mail2})
[[ -n $opgp_key ]] && echo -e "$opgp_key\n" || echo -e "No key found\n"
elif [ $option_tools = "3" ]; then
ua_id=$(echo $x | grep -sEi "ua|pub" | tr -d '-' | cut -s -d '-' -f -2); if [ -n $ua_id ]; then
echo -e "\n$ua_id\n"; curl -s -m 20 "https://api.hackertarget.com/analyticslookup/?q=${ua_id}"; echo ''; fi
elif [ $option_tools = "4" ]; then
echo -e "\n\n* $x\n"; cat $path_nmap_mac_pfx | grep -i $(echo $x | tr -d '/:' | cut -c -6) | sed 's/^/  /'; fi; done | tee -a ${out}; fi; fi 
unset x; unset target_type; f_removeDir; f_Menu
;;
#************** AS & IX INFO, PREFIX BGP STATUS **************
a|as|asn|prefix|ix|bgp)
f_makeNewDir; f_Long; f_optionsBGP; echo -e -n "\n    ${B}?${D}   "; read option_bgp
if [ $option_bgp = "1" ] || [ $option_bgp = "2" ] || [ $option_bgp = "3" ] || [ $option_bgp = "4" ]; then
bgp_details="true"; domain_enum="false"; option_detail="2"
[[ $option_bgp = "1" ]] && target_type="prefix"; [[ $option_bgp = "2" ]] && target_type="as"
[[ $option_bgp = "3" ]] && target_type="as"; [[ $option_bgp = "4" ]] && target_type="ix"
if [ $option_bgp = "1" ]; then
echo -e "${B}\nPREFIX BGP/ROA STATUS > ${G} Expected input:${D}${bold} IPv4/IPv6 BGP prefix ${D}\n"
out="${outdir}/PREFIX_BGP_STATUS.${file_date}.txt"
elif [ $option_bgp = "2" ]; then
echo -e "${B}\nAS DETAILS > ${G} Expected input:${D}${bold} AS number ${D}\n"
elif [ $option_bgp = "3" ]; then
echo -e "${B}\nANNOUNCED PREFIXES > ${G} Expected input:${D}${bold} AS number ${D}\n"
elif [ $option_bgp = "4" ]; then
echo -e "${B}\nIX INFO > ${G} Expected input:${D}${bold} IX ID ${D}\n"; fi
f_Long; f_setTARGET
for x in $(cat $tempdir/targets.list); do
if [ $option_bgp = "1" ]; then
curl -s -m 7 --location --request GET "https://stat.ripe.net/data/prefix-overview/data.json?resource=${x}&min_peers_seeing=2" > $tempdir/pov.json
announced=$(jq -r '.data.announced' $tempdir/pov.json); echo '' | tee -a ${out}; f_HEADLINE2 "$x\n\n" | tee -a ${out}
f_ROUTE "${x}" | tee -a ${out}; [[ $announced = "true" ]] && f_BGP_UPDATES "${x}" | tee -a ${out} && echo '' | tee -a ${out}
f_ROUTE_CONS "${x}" | tee -a ${out}; echo '' | tee -a ${out}; else
target_object=$(echo $x | tr [:upper:] [:lower:] | tr -d 'as' | tr -d 'ix' | tr -d 'id' | tr -d ' ' | sort -ug)
if [ $option_bgp = "2" ]; then
out="${outdir}/AS.${target_object}.${file_date}.txt"; f_AS_INFO "$target_object" | tee -a ${out}
elif [ $option_bgp = "3" ]; then
out="${outdir}/AS.${target_object}_PREFIXES.${file_date}.txt"; f_bgpPREFIXES "$target_object" | tee -a ${out}
elif [ $option_bgp = "4" ]; then
out="${outdir}/IX.${target_object}.${file_date}.txt"; curl -s "https://api.bgpview.io/ix/$ixid" > $tempdir/ix.json
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo -e " IX | ID  $ixid | $(jq -r '.data.name' $tempdir/ix.json)" | tee -a ${out}
f_Long | tee -a ${out}; echo '' | tee -a ${out}
jq -r '.data | {Name_short: .name, Descr: .name_full, Members: .members_count, City: .city, Country: .country_code, Website: .website, TechMail: .tech_email, TechPhone: .tech_phone, PolicyMail: .policy_email, PolicyPhone: .policy_phone, Statistics: .url_stats}' $tempdir/ix.json |
tr -d '{,"}' | sed 's/^ *//' | sed '/null/d' | sed '/^$/d' | sed 's/Name_short:/Name:       /' | sed 's/Name_full:/            /' |
sed 's/Website:/Website:    /' | sed 's/TechMail:/TechMail:   /' | sed 's/TechPhone:/TechPhone:  /' |
sed 's/PolicyMail:/PolicyMail: /' | sed 's/City:/City:       /' | sed 's/Country:/Country:    /' |
sed 's/Statistics:/Statistics: /' | sed 's/Members:/Members:    /' | sed '/Members:/G' |
sed 's/Descr:/Descr:      /' | sed '/Country:/G' | tee -a ${out}
echo ''; f_Long; echo -e "\n${B}Options  > ${G} List members?\n"
echo -e "${B} [1]${D} ASNs only" ; echo -e "${B} [2]${D} Members, incl. AS Names, Orgs & IP Addresses"
echo -e "${R} [0]${D} SKIP" ; echo -e -n "\n   ${B}?${D}  " ; read option_members
if ! [ $option_members = "0" ]; then
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo -e "MEMBERS\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' | tee -a ${out}
if [ $option_members = "1" ]; then
jq -r '.data.members[] | .asn' $tempdir/ix.json | sort -ug | tr '[:space:]' ' ' | sed 's/ /  /' | sed 's/^ *//' |
fmt -s -w 60 | sed G | tee -a ${out}
elif [ $option_members = "2" ] ; then
jq -r '.data.members[] | {ASN: .asn, NAME: .name, DESCR: .description, CC: .country_code, IPv4: .ipv4_address, IPv6: .ipv6_address}' $tempdir/ix.json |
tr -d '{,"}' | sed 's/^ *//' | sed '/null/d' | sed '/^$/d' | tr '[:space:]' ' ' | sed 's/ASN:/\nASN:/g' | sort -u |
sed 's/ASN: /\n\n/g' | sed 's/NAME: /\n\n/g' | sed 's/DESCR:/|/g' | sed 's/CC:/|/g' | sed 's/IPv4: /\n\n/g' |
sed 's/IPv6://g' | tee -a ${out}; echo -e "\n" | tee -a ${out}; fi; fi; fi; fi; f_CLEANUP_FILES; done
echo ''; unset rir; unset target_type; fi; f_removeDir; f_Menu
;;
#************** DOMAIN RECON *******************
d|dom|domain|domains|subdomains|recon)
f_makeNewDir; unset target; nmap_ns="--dns-servers=9.9.9.9,1.1.1.1"
f_optionsDOMAIN; echo -e -n "\n    ${B}?${D}   "; read option_domain
if [ $option_domain != "b" ]; then
if [ $option_domain = "3" ]; then
domain_enum="false"; target_type="hostname"; resolve_all=''; include_subdomains="true"; echo ''; f_Long; f_setTARGET
for x in $(cat $tempdir/targets.list); do
[[ -f $tempdir/dnsnames ]] && rm $tempdir/dnsnames; out="${outdir}/DOMAIN_CRT_ISSUANCES.${x}.txt"
f_CERT_SPOTTER "$x"
if [ -f $tempdir/dnsnames ]; then
echo ''; f_Long; echo -e "\nHosts\n"
f_RESOLVE_HOSTS4 "$tempdir/dnsnames" | tee $tempdir/dnsnames_resolved
echo ''; f_Long; echo -e "\nIP Addresses\n"
f_EXTRACT_IP4 "$tempdir/dnsnames_resolved" | tr '[:space:]' ' ' | fmt -w 60; echo ''; fi; done | tee -a ${out}; else
f_Long; echo -e -n "\n${B}Target  > ${G}DOMAIN  ${B}>>${D}  " ; read x
domain_enum="true"; page_details="true"; send_ping="false"; target_type="default"; bgp_details="false"; option_detail="2"
dns_details="true"; dig_array+=(@9.9.9.9); nssrv="9.9.9.9"; nssrv_dig="@9.9.9.9"; dns_lod="1"
dig_array+=(+noall +answer +noclass +ttlid)
if [ $option_domain = "1" ]; then
#************** Settings option_domain = 1 **************
out="${outdir}/DOMAIN_${x}.${file_date}.txt"; isp_contacts="true"; option_dns_details="1"
if [ $option_connect = "0" ]; then
option_source="1"; ww="true"; ww_source="1"; rfc1912="false"; else
option_source="2"; rfc1912="true"; option_starttls="0"; tls_port="443"; option_testssl="0"
echo -e "\n${B}Option  > ${G}curl ${B}> ${G} User Agent\n"
echo -e "${B} [1]${D} default" ; echo -e "${B} [2]${D} $ua_moz" ; echo -e -n "\n${B}  ? ${D}  " ; read option_ua
[[ $option_ua = "2" ]] && curl_ua="-A $ua_moz" || curl_ua=''
echo -e "\n${B}Options >${G} WhatWeb Website Data${B}\n"; echo -e "${B}[1]${D} hackertarget.com API"
echo -e "${B}[2]${D} Local App"; echo -e "${R}[0]${D} SKIP"; echo -e -n "\n${B}  ?${D}  "; read ww_source
[[ $ww_source = "0" ]] && ww="false" || ww="true"; fi; fi 
#************** Settings option_domain = 1 & 3 **************
echo -e -n "\n${B}Option  > ${G}whois ${B}>${D} Look up whois info for network ranges ${B}[y] | [n] ?${D}  " ; read option_whois
if [ $option_domain = "2" ] && [ $option_whois = "y" ]; then
echo -e -n "\n${B}Option  > ${G}whois ${B}>${D} Look up whois details for PoCs ${B}[y] | [n] ?${D}  " ; read option_whois2
[[ $option_whois2 = "y" ]] && isp_contacts="true" || isp_contacts="false"; fi
echo -e -n "\n${B}Option  > ${G}Zone Transfer (API) ${B}> ${D} Check for unauthorized zone transfers   ${B}[y] | [n] ?${D}  " ; read option_axfr
echo -e "\n${B}Options > ${G}Subdomains\n"; echo -e "${B} [1]${D} Subdomains (IPv4)"
echo -e "${B} [2]${D} Subdomains (IPv4, IPv6)"; echo -e -n "\n${B}  ?${D}  "  ; read option_subs
#************** option_domain = 2 **************
if [ $option_domain = "2" ]; then
out="${outdir}/SUBDOMAIN_ENUM_${x}.${file_date}.txt"
[[ $option_whois2 = "y" ]] && hline="SUBDOMAINS / ADDRESS RANGES / PoCs"
[[ $option_whois = "y" ]] && hline="SUBDOMAINS / ADDRESS RANGES" || hline="SUBDOMAINS"
echo '' | tee -a ${out}; f_HEADLINE "$x $hline  ($file_date)" | tee -a ${out}
echo "Sources: DNS records, hackertarget.com, certspotter.com" | tee -a ${out}
f_EXTRACT_IP4 $(dig @9.9.9.9 +short $x) > $tempdir/v4_uniq; f_DNS_SHORT "$x" | tee -a ${out}
[[ -f $tempdir/domain_ips ]] && cat $tempdir/domain_ips >> $tempdir/ips.list; else
#************** option_domain = 1 **************
#************** Get WhatWeb domain host DNS & domain whois/website status info **************
f_textfileBanner "${x}" >> ${out}; echo ''
dig @9.9.9.9 +short $x | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | tee $tempdir/v4_addresses > $tempdir/ip4.list
dig @9.9.9.9 aaaa +short $x | grep ':' > $tempdir/ip6.list
if [ $option_connect = "0" ] ; then
f_getPAGE_INFO "${x}"; [[ -f $tempdir/ww ]] && webpresence="true" || webpresence="false"
[[ $webpresence = "true" ]] && eff_url=$(cut -s -d ']' -f 1 $tempdir/ww | sed 's/\[/ /' | tail -1 | cut -d ' ' -f 1); else
error_code=6; curl -sfLk ${x} > /dev/null
if [ $? = ${error_code} ]; then
echo -e "\n${R} $x WEBSITE CONNECTION: FAILURE${D}\n\n"
echo -e "\n $x WEBSITE CONNECTION: FAILURE\n" >> ${out}
webpresence="false"; option_connect="0"; eff_url=''; else
echo -e "\n${D} $x WEBSITE CONNECTION: ${G}SUCCESS${D}\n"
webpresence="true"; declare -a curl_array=(); curl_array+=(-sLkv); f_getPAGE_INFO "$x"
endpoint_ip=$(grep -E "^IP:" $tempdir/response | awk -F'IP' '{print $NF}' | cut -d '(' -f 1 | sed 's/^[ \t]*//;s/[ \t]*$//')
eff_url=$(grep "^URL:" $tempdir/response | cut -d ':' -f 2- | sed 's/^ *//'); fi; fi
if [ -n "$eff_url" ]; then
target_host=$(echo $eff_url | sed 's/http:\/\///' | sed 's/https:\/\///' | cut -d '/' -f 1)
target_host4=$(dig @9.9.9.9 +short $target_host  | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
target_host6=$(dig @9.9.9.9 aaaa +short $target_host | grep ':')
[[ -n "$target_host4" ]] && echo "$target_host4" >> $tempdir/ip4.list
[[ -n "$target_host6" ]] && echo "$target_host6" >> $tempdir/ip6.list
if [ $target != $x ]; then
dig @9.9.9.9 aaaa +short $target  | grep ':' >> $tempdir/ip6.list
dig @9.9.9.9 +short $target  | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' >> $tempdir/ip4.list; fi
dig @9.9.9.9 aaaa +short $target_host  | grep ':' >> $tempdir/ip6.list
dig @9.9.9.9 +short $target_host  | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' >> $tempdir/ip4.list
[[ $target_host_dom != $x ]] && echo $target_host_dom >> $tempdir/domains_alt; fi
[[ -f $tempdir/ip4.list ]] && sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n -u $tempdir/ip4.list | tee $tempdir/v4_uniq > $tempdir/ips_all
[[ -f $tempdir/ip6.list ]] && grep ':' $tempdir/ip6.list | sort -uV  | tee $tempdir/v6_uniq >> $tempdir/ips_all
[[ $(cat $tempdir/v4_uniq | wc -w ) -gt 0 ]] && target4=$(cat $tempdir/v4_uniq)
[[ $(cat $tempdir/v6_uniq | wc -w ) -gt 0 ]] && target6=$(cat $tempdir/v6_uniq)
f_DOMAIN_STATUS "$x" | tee -a ${out}
#************** Domain webpresence **************
if [ $webpresence = "false" ]; then
f_Long | tee -a ${out}; echo -e "Domain Website not found. See further below for urlscan.io output (if applicable)" | tee -a ${out}; else
f_PAGE "$target" | tee -a ${out}
if ! [ $option_connect = "0" ]; then
f_handshakeHEADER "$target_host" > $tempdir/hndshake
if [[ $(sort -u $tempdir/ips_all | wc -w) = 1 ]]; then
f_printHANDSHAKE "$endpoint_ip"; else
echo '' | tee -a ${out}
if [ -n "$target_host4" ]; then
declare -a st_array=(); st_array+=(-s4Lkv)
for a in $target_host4; do
f_SERVER_INSTANCE "$a" | tee -a ${out}; f_printHANDSHAKE "$a"; done; unset a; fi
if [ -n "$target_host6" ]; then
declare -a st_array=(); st_array+=(-sLkv)
for z in $target_host6; do
f_SERVER_INSTANCE "$z" | tee -a ${out}; f_printHANDSHAKE "$z"; done; unset z; fi; fi
cat $tempdir/hndshake > ${outdir}/REDIRS+SSL_HANDSHAKE.${x}.${file_date}.txt; fi; fi
#************** urlscan.io (domain webpresence = "false") **************
[[ $webpresence = "false" ]] && [[ -f $tempdir/uscan_results ]] && cat $tempdir/uscan_results | tee -a ${out} && echo '' | tee -a ${out}
#************** DNS records & DNS record prefixes **************
echo '' | tee -a ${out}; target_type="dnsrec"; f_DNS_REC "$x" | tee -a ${out}
#************** SSL certificates (OpenSSL or certspotter API) **************
if [ $option_connect = "0" ]; then
include_subdomains="false"; f_CERT_SPOTTER "$x" | tee -a ${out}; else
serial_domain=$(echo | timeout 3 openssl s_client -connect ${x}:443 2>/dev/null | openssl x509 -noout -nocert -serial)
serial_target_host=$(echo | timeout 3 openssl s_client -connect ${target_host}:443 2>/dev/null | openssl x509 -noout -nocert -serial)
f_CERT_INFO "$x" | tee -a ${out}; [[ "$serial_domain" = "$serial_target_host" ]] || f_CERT_INFO "$target_host" | tee -a ${out}
if [ -n "$target4" ] && [[ $(echo "$target4" | wc -w) -gt 1 ]]; then 
ports_probe=$(echo "$target4" | head -1)
curl -s -m 7 "https://internetdb.shodan.io/$ports_probe" | jq -r '.ports[]?' > $tempdir/host_ports; fi
if [ -f $tempdir/host_ports ]; then
[[ $(grep -Ecow "143|993" $tempdir/host_ports) -gt 0 ]] && option_starttls="2" && f_CERT_INFO "$x" | tee -a ${out}
[[ $(grep -Ecow "25|465|587" $tempdir/host_ports) -gt 0 ]] && option_starttls="1" &&  f_CERT_INFO "$x" | tee -a ${out}; fi
option_starttls="1"; starttls_pro="smtp"; f_MX_CERTS "$x" | tee -a ${out}; fi
f_RECORD_DETAILS | tee -a ${out}; fi # option_domain = 1
#************** Zonetransfer **************
[[ $option_axfr = "y" ]] && [[ $option_domain = "2" ]] && cat $tempdir/dns_tmp | tee -a ${out}
[[ $option_axfr = "y" ]] && f_AXFR "${x}" | tee -a ${out}
#************** Subdomains / ASNs **************
include_subdomains="true"; cat $tempdir/v4_uniq >> $tempdir/ips.list
[[ $option_domain = "1" ]] && f_CERT_SPOTTER "$x" > ${outdir}/DOMAIN_CRT_ISSUANCES.${x}.txt || f_CERT_SPOTTER "$x" > $tempdir/cspotter
[[ $option_subs = "2" ]] && resolve_all='-R --resolve-all' || resolve_all=''; f_SUBS_HEADER "${x}" | tee -a ${out};
#************** Domain Networks, Whois, Network Ranges **************
unset rir; echo '' | tee -a ${out}
if [ $option_whois = "y" ]; then
f_HEADLINE "RIR WHOIS DATABASE OBJECTS  ($file_date)" > ${outdir}/NETWORK_RIR_OBJECTS_${x}.txt
echo -e "The following objects are searchable within the INVERSE whois search option [w1]\n" >> ${outdir}/NETWORK_RIR_OBJECTS_${x}.txt
echo -e "Supported RIRs: AFRINIC, APNIC & RIPE\n" >> ${outdir}/NETWORK_RIR_OBJECTS_${x}.txt
echo ''; f_Long; echo -e "\nGathering information about network ranges & service provider contacts ...\n"
if [ -f $tempdir/lacnic_nets ]; then
f_HEADLINE "NETWORKS (LACNIC)" > $tempdir/domain_nets; echo '' >> $tempdir/domain_nets
sed G $tempdir/lacnic_nets | sed 's/~/-/' >> $tempdir/domain_nets
[[ $(cat $tempdir/lacnic_nets | wc -l) -gt 5 ]] && echo '' >> $tempdir/domain_nets; fi
for addr in $(cat $tempdir/net_lookup.list); do
unset rir; unset netname; unset netname_table; unset pfx_addr; unset net_addr
[[ -f $tempdir/whois.json ]] && rm $tempdir/whois.json
[[ -f $tempdir/whois_records ]] && rm $tempdir/whois_records
f_getRIR "$addr"; if [ -n "$rir" ] && [ $rir != "lacnic" ]; then
curl -s -m 30 --location --request GET "https://stat.ripe.net/data/whois/data.json?resource=$addr" > $tempdir/whois.json
if [ $rir = "arin" ]; then
jq -r '.data.records[]?' $tempdir/whois.json | tr -d '[{,"}]' | sed 's/key://' | sed 's/value://' |
sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' > $tempdir/whois_records; else
jq -r '.data.records[-1]?' $tempdir/whois.json | tr -d '[{,"}]' | sed 's/key://' | sed 's/value://' |
sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' > $tempdir/whois_records; fi
check_cli=$(grep -so 'command line:' $tempdir/whois.json)
check_ianablk=$(jq -r '.data.records[]? | .[] | select (.key=="netname") | .value' $tempdir/whois.json | grep -o 'IANA-BLK')
if [ -z "$check_ianablk" ] && [ -z "$check_cli" ]; then
echo '' > $tempdir/domain_net
pfx_addr=$(grep -w "${addr}" $tempdir/net_table | cut -d '|' -f 2 | tr -d ' ' | head -1)
netname_table=$(grep -w "${addr}" $tempdir/net_table | cut -d '|' -f 3 | tr -d ' ' | head -1)
if [ $rir = "arin" ]; then
[[ $netname_table = "NA" ]] && query_addr="$addr" || query_addr="$pfx_addr"
netname=$(grep -E -A 1 "^NetName|^NetType" $tempdir/whois_records | sed '/--/d' | sed 's/NetType/|/' | tr '[:space:]' ' ' |
sed 's/NetName/\n/g' | grep -v 'Allocated to ARIN' | sed 's/^ *//' | cut -s -d '|' -f -1 | tail -1 | tr -d ' ')
if [ $netname_table = "NA" ]; then
f_HEADLINE "$netname  | ARIN |  $addr; $query_addr  (query)" >> $tempdir/domain_net; else 
f_HEADLINE "$netname_table  | ARIN |  $query_addr  (query)" >> $tempdir/domain_net; fi
abuse_mail=$(jq -r '.data.records[]? | .[] | select (.key=="OrgAbuseEmail") | .value' $tempdir/whois.json |
grep -E -v "ARIN|RIPE|APNIC|AFRINIC|LACNIC" | grep -E -v "@(arin|ripe|apnic|afrinic|lacnic)" | sort -u)
echo -e " $abuse_mail\n" >> $tempdir/domain_net
jq -r '.data.records[]? | .[] | select (.key=="NetRange", .key=="NetName", .key=="Organization") | .value' $tempdir/whois.json | sed '1,2d' |
grep -E -v "ARIN|RIPE|APNIC|AFRINIC|LACNIC" | sed '/)/G' | sed 's/^/ /' >> $tempdir/domain_net
jq -r '.data.records[]? | .[] | select (.key=="OrgId") | .value' $tempdir/whois.json |
grep -E -v "ARIN|RIPE|APNIC|AFRINIC|LACNIC" | sort -u >> $tempdir/arin_contacts; else
net_addr=$(jq -r '.data.records[]? | .[] | select (.key=="inetnum") | .value' $tempdir/whois.json | tr -d ' ')
netname=$(jq -r '.data.records[]? | .[] | select (.key=="netname") | .value' $tempdir/whois.json)
whois -h whois.$rir.net -- "--no-personal $net_addr" > $tempdir/whois
f_getRIR_OBJECTS "$tempdir/whois" >> ${outdir}/NETWORK_RIR_OBJECTS_${x}.txt
if [ $netname_table = "NA" ]; then
f_HEADLINE "$netname  | $(f_toUPPER "$rir") |  $addr; $net_addr  (query)" >> $tempdir/domain_net; else 
f_HEADLINE "$netname_table  | $(f_toUPPER "$rir") |  $addr; $net_addr  (query)" >> $tempdir/domain_net; fi 
abuse_mail=$(grep -sEa -m 1 "^% Abuse|^abuse-mailbox:|^e-mail:|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/whois |
grep -sEo "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b")
isp_admins=$(grep -E "^admin-c:" $tempdir/whois | head -5 | sort -u | awk '{print $NF}' | sed 's/^/,/' | tr -d ' ' | tr '[:space:]' ' ' |
sed 's/^\,//' | sed 's/ ,/, /g'; echo ''); net_orgs=$(f_ORG_SHORT "$tempdir/whois")
grep -E "^admin-c:" $tempdir/whois | awk '{print $NF}' | tr -d ' ' | head -3 >> $tempdir/${rir}_admins
[[ -n $abuse_mail ]] && echo -e " $abuse_mail\n" >> $tempdir/domain_net
if [ -n "$net_orgs" ]; then
grep -sEa -m 1 "^org:|^organisation:" $tempdir/whois | awk '{print $NF}' | tr -d ' ' >> $tempdir/${rir}_orgs
echo -e " $net_orgs\n" >> $tempdir/domain_net; else
descr=$(sed -e '/./{H;$!d;}' -e 'x;/route:/d' $tempdir/whois | grep -sEa -m 1 "^descr:" | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
[[ -n "$descr" ]] && echo -e " $descr\n" >> $tempdir/domain_net; fi
echo -e " ADMIN-C: $isp_admins\n" >> $tempdir/domain_net; fi
if [ $netname_table != "NA" ]; then
networks=$(grep -w "$netname_table" $tempdir/net_table | cut -d '|' -f 2 | sed 's/^[ \t]*//;s/[ \t]*$//' | sort -u |
sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -w 80)
num_nets=$(echo "$networks" | wc -w)
echo -e "\n'$netname_table' - IPv4 Prefixes: $num_nets  (target domain only)\n" >> $tempdir/domain_net
echo -e "$networks\n" | sed 's/^/ /' >> $tempdir/domain_net; fi
if [ $netname_table != "NA" ]; then
f_RESOURCES_NETNAME "$netname_table" >> $tempdir/domain_net; else
[[ $(f_countW "$netname") = 1 ]] && f_RESOURCES_NETNAME "$netname" >> $tempdir/domain_net; fi
cat $tempdir/domain_net >> $tempdir/domain_nets; rm $tempdir/domain_net; fi; unset rir; fi; done
#************** Service provider contacts **************
if [ $isp_contacts = "true" ]; then
f_HEADLINE "SERVICE PROVIDER CONTACTS" | tee -a ${out}
if [ -f $tempdir/poc_lookups ]; then
for pl in $(cat $tempdir/poc_lookups); do
rir="lacnic"; timeout 40 whois -h whois.lacnic.net $pl > $tempdir/lacnic_poc
f_POC "$tempdir/lacnic_poc" | sed 's/^/ /' | sed 's/^ \*/\*/'; done | tee -a ${out}; unset rir; fi
if [ -f $tempdir/arin_contacts ]; then
for hdl in $(cat $tempdir/arin_contacts | sort -u); do
rir="arin"; timeout 40 whois -h whois.arin.net -- "o ! $hdl" > $tempdir/arin_poc
echo -e "* $hdl\n"; f_POC "$tempdir/arin_poc" | sed 's/^/  /'; done | tee -a ${out}; unset hdl; unset rir; fi
if [ -f $tempdir/ripe_orgs ]; then
for hdl in $(cat $tempdir/ripe_orgs | sort -u); do
rir="ripe"; echo -e "* $hdl\n\n"
timeout 40 whois -h whois.ripe.net -- "-B $hdl" | sed '/role:/{x;p;x;}' | sed '/person:/{x;p;x;}' > $tempdir/ripe_org
f_POC "$tempdir/ripe_org" | sed '/./,$!d' | sed 's/^/  /'; done | tee -a ${out}; unset hdl; unset rir; fi
if [ -f $tempdir/apnic_orgs ]; then
for hdl in $(cat $tempdir/apnic_orgs | sort -u); do
rir="apnic"; echo -e "* $hdl\n\n"
timeout 40 whois -h whois.apnic.net -- "-B $hdl" | sed '/role:/{x;p;x;}' | sed '/person:/{x;p;x;}' > $tempdir/apnic_org
f_POC "$tempdir/apnic_org" | sed '/./,$!d' | sed 's/^/  /'; done | tee -a ${out}; unset hdl; unset rir; fi
if [ -f $tempdir/afrinic_orgs ]; then
for hdl in $(cat $tempdir/afrinic_orgs | sort -u); do
rir="afrinic"; echo -e "* $hdl\n\n"
timeout 40 whois -h whois.afrinic.net -- "-B $hdl" | sed '/role:/{x;p;x;}' | sed '/person:/{x;p;x;}' > $tempdir/afrinic_org
f_POC "$tempdir/afrinic_org" | sed '/./,$!d' | sed 's/^/  /'; done | tee -a ${out}; unset hdl; unset rir; fi
if [ -f $tempdir/ripe_admins ]; then
for hdl in $(cat $tempdir/ripe_admins | sort -u); do
rir="ripe"; echo -e "* $hdl\n\n"
timeout 30 whois -h whois.ripe.net -- "-B $hdl" | sed '/role:/{x;p;x;}' | sed '/person:/{x;p;x;}' > $tempdir/ripe_poc
f_POC "$tempdir/ripe_poc" | sed '/./,$!d' | sed 's/^/  /'; done | tee -a ${out}; unset hdl; unset rir; fi
if [ -f $tempdir/apnic_admins ]; then
for hdl in $(cat $tempdir/apnic_admins | sort -u); do
rir="apnic"; echo -e "* $hdl\n\n"
timeout 30 whois -h whois.apnic.net -- "-B $hdl" | sed '/role:/{x;p;x;}' | sed '/person:/{x;p;x;}' > $tempdir/apnic_poc
f_POC "$tempdir/apnic_poc" | sed '/./,$!d' | sed 's/^/  /'; done | tee -a ${out}; unset hdl; unset rir; fi
if [ -f $tempdir/afrinic_admins ]; then
for hdl in $(cat $tempdir/afrinic_admins | sort -u); do
rir="afrinic"; echo -e "* $hdl\n\n"
timeout 30 whois -h whois.afrinic.net -- "-B $hdl" | sed '/role:/{x;p;x;}' | sed '/person:/{x;p;x;}' > $tempdir/afrinic_poc
f_POC "$tempdir/afrinic_poc" | sed '/./,$!d' | sed 's/^/  /'; done | tee -a ${out}; unset hdl; unset rir; fi; else
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo '' | tee -a ${out}; fi
#************** Print subdomains networks & netranges **************
echo -e "  Reminder:  Network names are not considered unique identifiers.\n" | tee -a ${out}
echo -e "  Watch out for false positives within the 'Resources for' sections.\n" | tee -a ${out}
cat $tempdir/domain_nets | tee -a ${out}; fi
#************** Print full list of subdomains **************
if [ -f $tempdir/print_subs ]; then
if [[ $(wc -l <$tempdir/print_subs) -lt 601 ]] || [[ $report = "false" ]]; then
cat $tempdir/print_subs | tee -a ${out}; else
f_HEADLINE "$s  SUBDOMAINS (IPV4)\n"; echo -e "\nOutput written to ${outdir}/SUBDOMAINS_${x}.txt"; fi; else
if [ -f ${outdir}/Subdomains_HT.${x}.txt ] && [[ $(cat $tempdir/print_subs | wc -l) -lt 601 ]] || [[ $report = "false" ]]; then
cat ${outdir}/Subdomains_HT.${x}.txt | tee -a ${out}; fi; fi
if [ $option_domain = "1" ]; then
[[ $webpresence = "true" ]] && [[ -f $tempdir/print_ld ]] && cat $tempdir/print_ld | tee -a ${out}; fi; fi
unset target; unset target_type; unset x; echo ''; fi; f_removeDir; f_Menu
;;
#************** DNS *******************
dns|mx|ns|zone|zonetransfer|dig|nslookup|nsec)
f_makeNewDir; f_Long; f_optionsDNS; echo -e -n "\n    ${B}?${D}   "; read option_dns
if ! [ $option_dns = "b" ] ; then
domain_enum="false"; target_type="dnsrec"; bgp_details="false"; quiet_dump="false"; option_testssl="0"
declare -a dig_array=()
#************** DOMAIN DNS RECORDS *******************
if [ $option_dns = "1" ] || [ $option_dns = "2" ]; then
option_starttls="0"; tls_port="443"; f_setTARGET
if [ $option_dns = "2" ]; then
dig_array+=(@9.9.9.9);  nssrv_dig="@9.9.9.9"; nssrv="9.9.9.9"; dns_lod="1"; else 
dns_lod="2"; if [ $option_connect = "0" ]; then
dig_array+=(@9.9.9.9); rfc1912="false"; nssrv_dig="@9.9.9.9"; nssrv="9.9.9.9"; nmap_ns="--dns-servers=9.9.9.9,1.1.1.1"; else
rfc1912="true"; echo -e "\n${B}Nameservers (System Defaults)${D}\n"; f_getSYSTEM_DNS
echo -e "\n\n${B}Options  > Settings > ${G}Name Server\n"; echo -e "${B} [1]${D} Use system defaults"; echo -e "${B} [2]${D} 9.9.9.9"
echo -e "${B} [3]${D} 1.1.1.1"; echo -e "${B} [4]${D} Set custom NS"; echo -e -n "\n${B}  ? ${D}  "; read option_ns
if [ $option_ns = "2" ] ; then
dig_array+=(@9.9.9.9); nssrv_dig="@9.9.9.9"; nssrv="9.9.9.9"; nmap_ns="--dns-servers=9.9.9.9"
elif [ $option_ns = "3" ] ; then
dig_array+=(@1.1.1.1); nssrv_dig="@1.1.1.1"; nssrv="1.1.1.1"; nmap_ns="--dns-servers=1.1.1.1"
elif [ $option_ns = "4" ] && [ ]; then
echo -e -n "\n${B}Set     >${G}  NAME SERVER  ${B} >>${D}   " ; read ns_input
nssrv=$(echo $ns_input | tr -d ' ')
dig_array+=(@nssrv) ; nssrv_dig="@${nssrv}"; nmap_ns="--dns-servers=${nssrv}"; else
nssrv_dig=''; nssrv=''; nmap_ns=''; fi; fi; echo -e "\n${B}Options  > ${G}IP Address Details & Reputation Check\n"
echo -e "${B} [1]${D}  IP Address Details"; echo -e "${B} [2]${D}  IP Address Reputation Check"
echo -e "${B} [3]${D}  BOTH"; echo -e "${R} [0]${D}  SKIP"; echo -e -n "\n${B}  ? ${D}  " ; read option_dns_details; fi
if [ $option_connect = "0" ]; then
echo -e "\n${B}Option   > ${G}Zonetransfer\n"; echo -e "${B} [1]${D}  Check for unauthorized AXFR (API)"; else
echo -e "\n${B}Option   > ${G}Zonetransfer & TCP/ICMP Ping\n"
echo -e "${B} [1]${D}  Check for unauthorized AXFR (API)"; echo -e "${B} [2]${D}  Ping Resource Records"; echo -e "${B} [3]${D}  BOTH"; fi
echo -e "${R} [0]${D}  SKIP"; echo -e -n "\n${B}  ? ${D}  " ; read dns_opt2
[[ "$dns_opt2" = "2" ]] || [[ "$dns_opt2" = "3" ]] && default_ttl=$(ping -c 1 127.0.0.1 | grep -so "ttl=.[0-9]${2,3}" | cut -s -d '=' -f 2 | tr -d ' ')
dig_array+=(+noall +answer +noclass +ttlid)
for x in $(cat $tempdir/targets.list); do
if [ $option_dns = "2" ] ; then
out="${outdir}/DNS_SUMMARIES_$file_date.txt"; f_DNS_SHORT "$x" | tee -a ${out}; else
out="${outdir}/DNS_$file_date.$x.txt"; f_DNS_REC "$x" | tee -a ${out}
[[ $option_connect != "0" ]] && f_CERT_INFO "$x" | tee -a ${out}
[[ $option_connect != "0" ]] && option_starttls="1" && starttls_pro="smtp" && f_MX_CERTS "$x" | tee -a ${out}
[[ $option_dns_details = "1" ]] || [[ $option_dns_details = "3" ]] && f_RECORD_DETAILS | tee -a ${out}
if [ $option_dns_details = "2" ] || [ $option_dns_details = "3" ]; then
f_HEADLINE "DNS RECORDS | IP REPUTATION LOOKUP" | tee -a ${out}
for i in $(cat $tempdir/rec_ips.list | sort -uV); do
f_IP_REPUTATION "${i}"; done | tee -a ${out}; fi; fi
unset starttls_port; unset tls_port; unset target_ip; unset starttls_pro; unset x; done
#************** SHARED NAME SERVERS *******************
elif [ $option_dns = "3" ] ; then
echo -e -n "\n${B}Shared NS > Target >${G} NAME SERVER ${B}>>${D}  " ; read targetNS ; echo ''
out="${outdir}/SharedNameserver_${targetNS}.txt" ; echo '' | tee -a ${out}
curl -s "https://api.hackertarget.com/findshareddns/?q=${targetNS}${api_key_ht}" > $tempdir/sharedns
f_HEADLINE "$targetNS  |  SHARED NS  ($file_date)" | tee -a ${out}
echo -e "DOMAINS: $(cat $tempdir/sharedns | wc -l)\n" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta' | tee -a ${out}
if [[ $(cat $tempdir/sharedns | wc -l) -gt 700 ]] ; then
cat $tempdir/sharedns | tee -a ${out}; else
echo -e "Resolving results...\n"
dig @9.9.9.9 +noall +answer +noclass +nottlid -f $tempdir/sharedns > $tempdir/sharedns_hosts
grep 'A' $tempdir/sharedns_hosts | sed '/NS/d' | sed '/CNAME/d' | awk '{print $1,"\n\t\t\t\t\t\t",$3}'
f_EXTRACT_IP4 "$(grep 'A' $tempdir/sharedns_hosts)" > $tempdir/ips_sorted
if [[ $(cat $tempdir/ips_sorted | wc -l) -lt 101 ]] ; then
cat $tempdir/ips_sorted > $tempdir/ips_sorted.list; else
cat $tempdir/ips_sorted | sort -t . -k 1,1n -k 2,2n -k 3,3n -u > $tempdir/ips_sorted.list; fi
echo '' | tee -a ${out}; f_whoisTABLE "$tempdir/ips_sorted.list"; f_Long | tee -a ${out}
cat $tempdir/whois_table.txt | cut -d '|' -f -5 | sed '/^$/d' | sed '/NET NAME/{x;p;x;G}' | tee -a ${out}
asns=$(cut -d '|' -f 1 $tempdir/whois_table.txt | grep -E -v "AS|NA" | sed '/^$/d' | tr -d ' ' | sort -uV)
if [ -n "$asns" ]; then
echo -e "\n___________________________________________________________\n\n" | tee -a ${out}
for as in $asns ; do
asn=$(dig +short as$as.asn.cymru.com TXT | tr -d "\"" | sed 's/^ *//' | cut -d '|' -f 1,5 | sed 's/ |/,/g')
echo -e "AS $asn"; done | tee -a ${out}; fi; fi
#************** ZONE TRANSFER *******************
elif [ $option_dns = "4" ]; then
unset target_ns; unset target_dom; echo -e -n "${B}\nZONE TRANSFER (API) > ${G} Expected input:${D}${bold}Domain name${D}\n"
if [ $option_connect = "0" ]; then
option_xfr="2"; else
echo -e "\n${B}Options  > ${G}Zone transfer${B}\n"
echo -e " ${B}[1] ${G} dig  ${B} Zone Transfer${D}  (probes all or specific domain name servers)"
echo -e " ${B}[2] ${G} API  ${B} Zone Transfer${D}  (probes all NS records)"
echo -e -n "\n${B}  ? ${D}  " ; read option_xfr; fi; echo -e -n "\n${B}Target >${G} Domain ${B}>>${D}  " ; read target_dom
if [ $option_xfr = "1" ]; then
out="${outdir}/ZONE_TRANSFER.${file_date}_${target_dom}.txt"; f_AXFR "$target_dom" | tee $tempdir/ztrans_results; else 
declare dig_array; dig_array+=(@9.9.9.9 +noall +answer +noclass +ttlid); echo '' | tee $tempdir/ztransfer
f_NS "$target_dom" | tee -a $tempdir/ztransfer
echo -e -n "\n\n${B}TARGET NS > [1]${D} Probe all NS records ${B}| [2]${D} Specific name server  ${B}?${D}  " ; read option_ns
if  [ $option_ns = "2" ] ; then
echo -e -n "\n${B}Target >${G} Name server ${B}>>${D}  " ; read target_ns
out="${outdir}/ZONE_TRANSFER.${file_date}_${target_dom}_${target_ns}.txt"
f_HEADLINE "$target_dom, $target_ns | ZONE TRANSFER | $(date -R)" | tee -a ${out}
dig axfr @${target_ns} $target_dom | sed '/;; global options:/d' | sed '/;; Query time:/{x;p;x;}' |
sed '/server found)/G' | tee $tempdir/ztrans_results; else
out="${outdir}/ZONE_TRANSFER.${file_date}_${target_dom}.txt"
f_HEADLINE "$target_dom | ZONE TRANSFER | $(date -R)" | tee -a ${out}; cat $tempdir/ztransfer >> ${out}
for i in $(cat $tempdir/ns_servers); do
dig axfr @${i} $target_dom | sed '/;; global options:/d' | sed '/;; Query time:/{x;p;x;}' |
sed '/server found)/G'; done | tee $tempdir/ztrans_results; fi; cat $tempdir/ztransfer >> ${out}; fi 
if [ -f $tempdir/ztrans_results ]; then
cat $tempdir/ztrans_results >> ${out}; egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $tempdir/ztrans_results |
sort -t . -k 1,1n -k 2,2n -u > $tempdir/ips_sorted
echo '' | tee -a ${out}; f_whoisTABLE "$tempdir/ips_sorted"; f_Long | tee -a ${out}
cat $tempdir/whois_table.txt | cut -d '|' -f -5 | sed '/^$/d' | sed '/NET NAME/{x;p;x;G}' | tee -a ${out}
asns=$(cut -d '|' -f 1 $tempdir/whois_table.txt | grep -E -v "AS|NA" | sed '/^$/d' | tr -d ' ' | sort -uV)
if [ -n "$asns" ]; then
echo -e "\n___________________________________________________________\n\n" | tee -a ${out}
for as in $asns ; do
asn=$(dig +short as$as.asn.cymru.com TXT | tr -d "\"" | sed 's/^ *//' | cut -d '|' -f 1,5 | sed 's/ |/,/g')
echo -e "AS $asn"; done | tee -a ${out}; fi; fi
#************** DIG BATCH MODE (DNS MASS LOOKUP) *******************
elif [ $option_dns = "5" ] ; then
echo -e -n "${B}\nDIG BATCH MODE > ${G} Expected input:${D}${bold}File containing host-/domain names${D}\n"
echo -e "\n${B}Options  > dig >${G} Record Types\n"; echo -e "${B} [1]${D} A"; echo -e "${B} [2]${D} AAAA"
echo -e "${B} [3]${D} NS"; echo -e "${B} [4]${D} MX"; echo -e "${B} [5]${D} SRV";  echo -e -n "\n${B}  ? ${D}  " ; read option_rr
echo -e -n "\n${B}INPUT FILE >${G} Path to file  ${B}>>${D}  " ; read input
if [ $report = "true" ]; then
echo -e -n "\n${B}OUTPUT FILE >${G} Path to file  ${B}>>${D}  " ; read output; out="${outdir}/${output}.${file_date}.txt"; fi
echo -e "\n${B}Nameservers (System Defaults)${D}\n"; f_getSYSTEM_DNS
echo -e "\n${B}Options  > ${D} Nameservers ${B}>\n"; echo -e "${B} [1]${D} Use system defaults"
echo -e "${B} [2]${D} 9.9.9.9"; echo -e "${B} [3]${D} 1.1.1.1"; echo -e "${B} [4]${D} Set custom NS"; echo -e -n "\n${B}  ? ${D}  " ; read option_ns
[[ $option_ns = "2" ]] && dig_array+=(@9.9.9.9); [[ $option_ns = "3" ]] && dig_array+=(@1.1.1.1)
[[ $option_ns = "4" ]] && echo -e -n "\n${B}Set     >${D} Nameserver  ${B} >>${D}   " ; read nssrv && dig_array+=(@nssrv)
[[ $option_rr = "1" ]] && record="A"; [[ $option_rr = "2" ]] && dig_array+=(aaaa); record="AAAA"
[[ $option_rr = "3" ]] && dig_array+=(ns); record="NS"; [[ $option_rr = "4" ]] && dig_array+=(mx); record="MX"
[[ $option_rr = "5" ]] && dig_array+=(srv); record="SRV"; dig_array+=(+noall +answer +noclass +ttlid)
f_HEADLINE "DIG BATCH MODE | RECORD TYPE: $record | $file_date" | tee -a ${out}
dig ${dig_array[@]} -f ${input} | tee -a ${out} ; echo '' | tee -a ${out}
#************** MAIL SERVER SSL *******************
elif [ $option_dns = "6" ] ; then
if [ $option_connect != "0" ]; then
quiet_dump="false"; dig_array+=(@9.9.9.9); dig_array+=(+noall +answer +noclass +ttlid)
echo -e "\n${B}Options  > ${G}MAIL SERVER SSL STATUS\n"; echo -e "${B} [1]${D}  Domain MX Records - SSL"
echo -e "${B} [2]${D}  Mail Server (other)"; echo -e -n "\n${B}  ?${D}   "  ; read option_mx_type
if [ $option_mx_type = "1" ]; then
target_type="mailserv"; option_starttls="1";  else
target_type="hostname"; echo -e "\n${B}Options  > ${G} StartTLS Protocol\n"
echo -e "${B} [1]${D} SMTP"; echo -e "${B} [2]${D} IMAP"; echo -e "${B} [3]${D} POP3"
echo -e -n "\n${B}  ?${D}   "; read option_starttls; fi; echo ''; f_Long; f_setTARGET
for x in $(cat $tempdir/targets.list); do
if [ $option_mx_type = "1" ]; then
out="${outdir}/MXssl_${x}_${file_date}.txt"
echo ''; f_HEADLINE "$x  | MX RECORDS SSL/TLS | $file_date"; echo -e "\n$x  DOMAIN HOST\n\n"; f_dnsCHAIN "$x"
f_MX "$x"; f_MX_CERTS; else
out="${outdir}/MAILSRV_SSL.${x}_${file_date}.txt"
f_HEADLINE "$x"; echo "DNS" | sed -e :a -e 's/^.\{1,78\}$/ &/;ta'; f_dnsCHAIN "$x"; echo ''
f_CERT_INFO "$x"; fi; done | tee -a ${out}; fi; fi
unset target_type; unset x; echo ''; fi; f_removeDir; f_Menu
;;
h|help|all|about) f_showHELP ;;
#************** IPV4 HOSTS THREAT ENUM, BLOCKLISTS, CVES *******************
ip|ipv4|blocklist|blocklists|blacklists|cve|cves|vhosts)
f_makeNewDir; unset rir; f_Long; f_optionsHOSTS; echo -e -n "\n${B}    ?${D}   "  ; read option_enum
if ! [ $option_enum = "b" ]; then
option_detail="1"; domain_enum="false"; option_connect="0"; bgp_details="false"; echo ''
[[ $option_enum = "1" ]] && target_type="default" && threat_enum="true" && f_get_IX_PFX
[[ $option_enum = "2" ]] && target_type="default"
[[ $option_enum = "3" ]] && target_type="host_blcheck" && out="${outdir}/BLcheck.HOSTS.${file_date}.txt"
[[ $option_enum = "4" ]] && target_type="other" && out="${outdir}/CVE_Check_API.${file_date}.txt"
echo ''; f_Long; f_setTARGET
[[ $option_enum = "3" ]] && f_HEADLINE "BLOCKLIST CHECK  |  $file_date" | tee -a ${out}
[[ $option_enum = "4" ]] && f_HEADLINE "CVE CHECK  [SOURCE: SHODAN]  |  $file_date" | tee -a ${out}
targets_sorted=$(f_EXTRACT_IP4 "$tempdir/targets.list")
for x in $targets_sorted; do
f_CLEANUP_FILES; if [ $option_enum = "1" ]; then
out="${outdir}/HOSTS.IP_REP.${file_date}.txt"; echo ''; f_HOST_DEFAULT "${x}"
elif [ $option_enum = "2" ]; then
out="${outdir}/REVERSE_IP.$x.${file_date}.txt"; f_VHOSTS "${x}"; cat $tempdir/vhosts_out
elif [ $option_enum = "3" ]; then
echo -e "\n$x\n"; f_IP_REPUTATION "$x"
elif [ $option_enum = "4" ]; then
f_CVES "$x"; fi; done | tee -a ${out}; unset target_type; unset x; unset rir; echo ''; f_Long; f_targetCONNECT; fi; f_removeDir; f_Menu
;;
m) echo '' ; f_Long; f_optionsMTU ;;
#************** NETWORK OPTIONS *******************
n|net|nets|networks|prefix|prefixes|pfx|banners|pingsweep|arp|rdns)
f_makeNewDir; f_Long; unset rir; file_date=$(date -I); target_type="net"; domain_enum="false"; set_output="true"
f_optionsNET ; echo -e -n "\n${B}    ?${D}   " ; read option_enum
if ! [ $option_enum = "b" ] ; then
#************** - NETWORK ADDRESS SPACE ENUM - **************
[[ $option_enum = "6" ]] && target_type="net_blcheck" || target_type="net"
if [ $option_enum = "2" ]; then
target_type="net"; out="${outdir}/ADDR_SPACE_ENUM.${file_date}.txt"; f_setTARGET
echo -e -n "\n${B}Options  > ${D}Filter results ${B}[y] | [n]  ?${D}  " ; read option_filter
if [ $option_filter = "y" ] ; then
echo -e -n "\n${B}Filter  > ${D}Single Searchterm or csv - e.g. access,backbone,service  ${B}>>${D}  " ; read filter
echo "$filter" | tr -d ' ' | sed 's/,/\n/g' | tr -d ' ' > $tempdir/filters; fi
echo '' | tee -a ${out}; f_HEADLINE "PREFIX ADDRESS SPACE / SUBNET SEARCH | $file_date" | tee -a ${out}
if [ $option_filter = "y" ] ; then
echo -e "\nSearching for ...\n" | tee -a ${out} ; cat $tempdir/filters | tee -a ${out}
echo -e "\nwithin\n" | tee -a ${out} ; cat $tempdir/targets.list | tee -a ${out}; else
echo -e "\nSearching within ...\n" | tee -a ${out} ; cat $tempdir/targets.list | tee -a ${out}; fi
echo '' | tee -a ${out}; for x in $(cat $tempdir/targets.list); do
net_ip=$(echo $x | cut -d '/' -f 1 | tr -d ' ')
if [[ ${x} =~ ":" ]] ; then
option_type="2"
elif [[ ${net_ip} =~ $REGEX_IP4 ]] ; then
option_type="1"; fi; f_HEADLINE "${x}"; f_getRIR "$x"; f_getLESS_SPECIFICS "$x"; f_getMORE_SPECIFICS "$x"
f_CLEANUP_FILES; done | tee -a ${out}
#************** - LAN SERVICE DISCOVERY BROAD- & MULTICASTS) - **************
elif [ $option_enum = "9" ]; then
ip -6 addr show | grep -s 'state UP' | cut -d ':' -f 2 | sed 's/^[ \t]*//;s/[ \t]*$//' > $tempdir/iflist6
out="${outdir}/LAN_DISCOVERY.${file_date}.txt"; f_HEADLINE "LOCAL NETWORK SERVICE DISCOVERY  ($file_date)" | tee -a ${out}
f_IFLIST | tee -a ${out}; f_NMAP_BCAST "broadcast-dhcp-discover" | tee -a ${out}
f_DUMP_ROUTER_DHCP_6 | tee -a ${out}; f_NMAP_BCAST "broadcast-dns-service-discovery" | tee -a ${out}
f_Long ; echo -e "${B}Options > ${G}Broad-/Multicastscasts I\n"
echo -e "${B} [1]${D} RIP2 Discover"; echo -e "${B} [2]${D} OSPF2 Discover"
echo -e "${B} [3]${D} BOTH" ; echo -e "${R} [0]${D} SKIP"
echo -e -n "\n${B}  ? ${D}  " ; read discoverI
[[ $discoverI = "1" ]] || [[ $discoverI = "3" ]] && f_NMAP_BCAST "broadcast-rip-discover" | tee -a ${out}
[[ $discoverI = "2" ]] || [[ $discoverI = "3" ]] && f_NMAP_BCAST "broadcast-ospf2-discover" | tee -a ${out}
f_Long; echo -e "${B}Options > ${G}Broad-/Multicastscasts II\n"
echo -e "${B} [1]${D} UPNP Info"; echo -e "${B} [2]${D} IGMP Discovery"
echo -e "${B} [3]${D} BOTH" ; echo -e "${R} [0]${D} SKIP"
echo -e -n "\n${B}  ? ${D}  " ; read discoverII
[[ $discoverII = "1" ]] || [[ $discoverII = "3" ]] && f_NMAP_BCAST "broadcast-upnp-info" | tee -a ${out}
[[ $discoverII = "2" ]] || [[ $discoverII = "3" ]] && f_NMAP_BCAST "broadcast-igmp-discovery" | tee -a ${out}
elif [ $option_enum = "7" ]; then
out="${outdir}/DUPLICATES.${file_date}.txt"
f_HEADLINE "IPV4 DUPLICATES DETECTION  ($file_date)" | tee -a ${out}
f_printLAN | tee -a ${out}; echo ''; f_setTARGET
for x in $(cat $tempdir/targets.list); do
sudo ${PATH_nmap} -R --resolve-all --system-dns -PN -p 22,443,445 --script=duplicates,nbstat,ssl-cert,ssh-hostkey $x 2>/dev/null > $tempdir/duplicates
f_Long; if [[ $(grep -c 'duplicates:' $tempdir/duplicates) -gt 0 ]]; then
sed -n '/duplicates:/,$p' $tempdir/duplicates | grep '|' | sed '/|_/G' | tr -d '|_' | sed 's/duplicates:/\nDUPLICATES:\n/' |
sed 's/^[ \t]*//;s/[ \t]*$//'  | tee -a ${out}; else
echo -e "\nNo duplicates found\n"  | tee -a ${out}; fi
echo -e -n "\n${B}Option  >  ${D} Display full Nmap output ${B}[y] | [n] ?${D}  " ; read show_output
if [ $show_output = "y" ]; then
grep -E "^Nmap scan report|^Nmap done|Host is|Host seems|open|filtered|MAC Address:|^Post-scan|\|" $tempdir/duplicates | tr -d '|_' |
grep -E -v "MD5:|Subject Alternative|Public Key type:|Public Key bits:|Signature Algorithm:|Not valid before:" |
sed '/Nmap scan report/i \\n_______________________________________________________________________________\n' | sed 's/^[ \t]*//;s/[ \t]*$//' |
sed '/scan report/G' | sed 's/Nmap scan report for //' | sed '/Host is/G' | sed '/Host seems/G' | sed 's/Host is up/UP/' |
sed '/MAC Address:/{x;p;x;}' | sed 's/nbstat:/\nnbstat:\n/' | sed 's/ssl-cert:/\nssl-cert:\n/' |
sed '/Post-scan script/i \\n_______________________________________________________________________________\n' |
sed '/Nmap done/i \\n_______________________________________________________________________________\n' | 
sed 's/duplicates:/\nduplicates:\n/' | sed '/Nmap done:/G' | sed 's/^ *//' | tee -a ${out}; fi; done
elif [ $option_enum = "8" ]; then
out="${outdir}/IOT.${file_date}.txt"
f_HEADLINE "IOT SERVICES / DEVICES  ($file_date)" | tee -a ${out}
f_printLAN | tee -a ${out}
sudo ${PATH_nmap} --script=knx-gateway-discover 2>/dev/null | grep -E "\||\|_" | sed 's/^|_//g' | sed 's/^|//g' |
sed 's/knx-gateway-discover:/\n\nKNX-Gateways\n_____________\n\n/' | tee -a ${out}
echo ''; f_setTARGET; echo '' | tee -a ${out}
for x in $(cat $tempdir/targets.list); do
sudo nmap -sV -sS -sU -Pn -T4 --version-intensity 4 --open -p T:102,T:502,T:1883,U:47808 --script=bacnet-info,mqtt-subscribe,s7-info,modbus-discover
--script-args='modbus-discover.aggressive=false' 2> /dev/null $x > $tempdir/nmap_iot; f_printNMAP1 "$tempdir/nmap_iot"; done | tee -a ${out}
else # --- end section option_enum = 2, 8 & 9
if [ $report = "false" ]; then
option_filename="n"; custom_file="false"; else
echo -e -n "\n${B}Option > ${D}Set Custom Name for Output File ${B}[y] | [n]  ?${D}  " ; read option_filename
if [ $option_filename = "y" ]; then
custom_file="true"; echo -e -n "\n${B}Output > ${G}OUTPUT - FILE NAME ${B}>>${D}  " ; read filename; out=${outdir}/$filename.txt; else
custom_file="false"; fi; fi
#************** - BLOCKLISTS CHECK / PING SWEEP - **************
[[ $option_enum = "3" ]] && psweep="true"
[[ $option_enum = "4" ]] || [[ $option_enum = "5" ]] && psweep="false"
[[ $option_enum = "6" ]] && option_scope="2" && psweep="false"
#**************  CONFIG - OPTION 1) **************
if [ $option_enum = "1" ]; then
f_get_IX_PFX; option_scope="2"; option_filter="n"; echo -e "\n${B}Options  > ${G}Type ${B}>\n"
echo -e "${B} [1]${D} IPv4 Network(s)" ; echo -e "${B} [2]${D} IPv6 Network(s)"
echo -e -n "\n${B}  ?${D}   "  ; read option_type; f_setTARGET; echo ''; f_Long
echo -e "\n${B}Options  > ${G}DETAILS I > Network whois\n"
echo -e "${B} [1]${D} Network Whois ${bold}Overview${D}"; echo -e "${B} [2]${D} Network ${bold}Contact Details${D}"
echo -e "${B} [3]${D} ${bold}Brief summary${D} only\n"
echo -e -n "\n${B}  ? ${D}  " ; read option_netdetails1
[[ $option_netdetails1 = "1" ]] && option_detail="3"; [[ $option_netdetails1 = "2" ]] && option_detail="2"
[[ $option_netdetails1 = "3" ]] && option_detail="0"
echo -e "\n${B}Options  > ${G}DETAILS II\n"
echo -e "${B} [1]${D} Geographic distribution, subnets & related prefixes"
echo -e "${B} [2]${D} Search additional resources by network name\n"
echo -e "${B} [3]${D} BOTH"; echo -e "${R} [0]${D} SKIP"; echo -e -n "\n${B}  ? ${D}  " ; read option_netdetails2
echo -e "\n${B}Options  > ${G}DETAILS III > Rev. DNS Lookup Zones & Ping Sweep\n"
echo -e "${B} [1]${D} List Rev. DNS Lookup Zones (RIPE only)"
if [ $option_connect = "0" ] || [ $option_type = "2" ]; then
psweep="false"; echo -e "${B} [2]${D} Ping Sweep - not available for IPv6 / non-target-connect mode"; else
echo -e "${B} [2]${D} Ping Sweep (Nmap)\n"
echo -e "${B} [3]${D} BOTH"; fi; echo -e "${R} [0]${D} SKIP"; echo -e -n "\n${B}  ? ${D}  " ; read option_netdetails3
if [ $option_netdetails3 = "2" ] || [ $option_netdetails3 = "3" ]; then
psweep="true"; else
psweep="false"; fi
if [ $option_type = "2" ]; then
net_dns="0"; option_netdetails4="0";option_netdetails5="0"
echo -e "\nSkipping IPv4 Options 'DETAILS IV/V - NETWORK DNS / SERVICE BANNERS / CVES'\n"; else
echo -e "\n${B}Options  > ${G}DETAILS IV > ${G}NETWORK rDNS & REVERSE IP (VHOSTS) I\n"
f_optionsNETDNS1; echo -e -n "\n${B}  ? ${D}  " ; read option_net_dns1
if [ $option_net_dns1 != "0" ]; then
if [ $option_net_dns1 = "1" ] || [ $option_connect = "0" ]; then
nmap_ns="--dns-servers=9.9.9.9,1.1.1.1"; else
echo -e -n "\n${B}Set     >${G} NAME SERVER  ${D}(2+ NS -> separate by comma) ${B} >>${D}   " ; read ns_input
nssrv=$(echo "$ns_input" | tr -d ' ');  nmap_ns="--dns-servers=${nssrv}"; fi; fi 
echo -e "\n${B}Options  > ${G}DETAILS IV > ${G}NETWORK rDNS & REVERSE IP (VHOSTS) II\n"
f_optionsNETDNS2; echo -e -n "\n${B}  ? ${D}  " ; read option_net_dns2
[[ $option_net_dns2 = "2" ]] || [[ $option_net_dns2 = "3" ]] && rdnsv6="true" || rdnsv6="false"
if [ $option_net_dns1 = "0" ]; then
[[ $option_net_dns2 = "0" ]] || [[ $option_net_dns2 = "2" ]] && net_dns="0"
[[ $option_net_dns2 = "1" ]] || [[ $option_net_dns2 = "3" ]] && net_dns="2"; else
[[ $option_net_dns2 = "0" ]] || [[ $option_net_dns2 = "2" ]] && net_dns="1"
[[ $option_net_dns2 = "1" ]] || [[ $option_net_dns2 = "3" ]] && net_dns="3"; fi 
[[ $net_dns = "0" ]] && option_netdetails4="0"; [[ $net_dns = "1" ]] && option_netdetails4="1"
[[ $net_dns = "2" ]] && option_netdetails4="2"; [[ $net_dns = "3" ]] && option_netdetails4="3"
echo -e "\n${B}Options  > ${G}DETAILS V > Service Banners / CPEs & CVEs\n"
echo -e "${B} [1] ${G}API${B} >${D}  Banners         (hackertarget.com IP API max. size: /16)"
echo -e "${B} [2] ${G}API${B} >${D}  CPEs & Vulners  (Shodan API)"
echo -e "\n${B} [3]${D} BOTH"; echo -e "${R} [0]${D} SKIP"; echo -e -n "\n${B}  ? ${D}  " ; read option_netdetails5; fi; fi
#************** - PING SWEEP CONFIG - **************
if [ $psweep = "true" ]; then
if [ $option_connect = "0" ]; then
echo -e "\nPlease enable target-connect mode\n"; else
echo -e -n "\n${B}Option   > ${D}Run Nmap with elevated priviliges ${B}[y] | [n]  ?${D}  " ; read option_root
if [ $option_enum =  "3" ]; then
echo -e "\n${B}Options  > ${G}PING SWEEP I\n"
echo -e "${B} [1]${D} Public IP address range"
echo -e "${B} [2]${D} Local Network - ARP ping"
echo -e "${B} [3]${D} Local Network - alternative probes (disable ARP)"
echo -e -n "\n${B}  ? ${D}  " ; read option_nettype
[[ $option_nettype = "1" ]] && option_scope="2"
[[ $option_nettype = "2" ]] && option_scope="1" && option_pingsweep="0"
[[ $option_nettype = "3" ]] && option_scope="1" && option_pingsweep="3"; fi
if [ $option_scope = "2" ]; then
[[ $option_enum =  "3" ]] && echo -e "\n${B}Options  > ${G}PING SWEEP II\n" || echo -e "\n${B}Options  > ${G}PING SWEEP\n"
echo -e "${B} [1]${D} Use Nmap Defaults"
echo -e "${B} [2]${D} Send more probes"; echo -e "${B} [3]${D} Customize options"
echo -e -n "\n${B}  ? ${D}  " ; read option_pingsweep; fi #end  option_scope
if [ $option_pingsweep = "3" ]; then
declare psweep_array
[[ $option_scope = "1" ]] && [[ $option_root = "y" ]] && psweep_array+=(--disable-arp-ping)
echo -e "\n${B}Options > ${G}PING${B} > PROTOCOLS${B} > ${G}TCP\n"
echo -e "${B} [1]${D} TCP SYN" ; echo -e "${B} [2]${D} TCP ACK"
echo -e "${B} [3]${D} BOTH" ; echo -e "${R} [0]${D} SKIP"
echo -e -n "\n${B}  ? ${D}  " ; read option_tcp
if [ $option_tcp = "1" ] || [ $option_tcp = "3" ]; then
echo -e -n "\n${B}Ports   > ${G} TCP SYN ${B}>  e.g. 25,80,135  ${B}>>${D}  " ; read syn_ports; psweep_array+=(-PS${syn_ports}); fi
if [ $option_tcp = "2" ] || [ $option_tcp = "3" ]; then
echo -e -n "\n${B}Ports   > ${G} TCP ACK ${B}>  e.g. 25,80,135  ${B}>>${D}  " ; read ack_ports; psweep_array+=(-PA${ack_ports}); fi
if [ $option_root = "y" ]; then
echo -e "\n${B}Options > ${G}PING${B} > PROTOCOLS${B} > ${G}ICMP${D}\n"
echo -e "${B} [1]${D} ICMP ECHO"
echo -e "${B} [2]${D} ICMP TIMESTAMP"; echo -e "${B} [3]${D} BOTH" ; echo -e "${R} [0]${D} SKIP"
echo -e -n "\n${B}  ? ${D}  " ; read option_icmp
[[ $option_icmp = "1" ]] || [[ $option_icmp = "3" ]] && psweep_array+=(-PE)
[[ $option_icmp = "2" ]] || [[ $option_icmp = "3" ]] && psweep_array+=(-PP)
echo -e "\n${B}Options > ${G}PING${B} > PROTOCOLS${B} > ${G}IP PROTOCOL SCAN\n"
echo -e "${B} [1]${D} IP Protocol Scan (sends multiple ICMP, IGMP & IP-in-IP packets)"
echo -e "${R} [0]${D} SKIP"; echo -e -n "\n${B}  ? ${D}  " ; read option_PO; [[ $option_PO = "1" ]] && psweep_array+=(-PO)
echo -e "\n${B}Options > ${G}PING${B} > PROTOCOLS${B} > ${G}UDP & SCTP\n"; echo -e "${B} [1]${D} SCT (Stream Control Transmission Protocol)"
echo -e "${B} [2]${D} UDP"; echo -e "${B} [3]${D} BOTH" ; echo -e "${R} [0]${D} SKIP"; echo -e -n "\n${B}  ? ${D}  " ; read option_udp
if [ $option_udp = "2" ] || [ $option_udp = "3" ]; then
echo -e -n "\n${B}Ports   > ${G} UDP ${B}>  e.g. 53,123     ${B}>>${D}  " ; read udp_ports; psweep_array+=(-PU${udp_ports}); fi
if [ $option_udp = "1" ] || [ $option_udp = "3" ]; then
echo -e -n "\n${B}Ports   > ${G} SCT ${B}>  e.g. 25,80,135  ${B}>>${D}  " ; read sct_ports; psweep_array+=(-PY${sct_ports}); fi
fi; fi; fi; fi
#************** - IPV4 DNS OPTIONS - **************
if [ $option_enum =  "4" ]; then
psweep="false"; echo ''; f_Long; echo -e "\n   ${B}Options  > ${G}NETWORK rDNS & REVERSE IP (VHOSTS) I\n"
f_optionsNETDNS1; echo -e -n "\n${B}  ? ${D}  " ; read option_net_dns1
if [ $option_net_dns1 != "0" ]; then
if [ $option_net_dns1 = "1" ] || [ $option_connect = "0" ]; then
nmap_ns="--dns-servers=9.9.9.9,1.1.1.1"; else
echo -e -n "\n${B}Set     >${G} NAME SERVER  ${D}(2+ NS -> separate by comma) ${B} >>${D}   " ; read ns_input
nssrv=$(echo "$ns_input" | tr -d ' ');  nmap_ns="--dns-servers=${nssrv}"; fi; fi
echo -e "\n   ${B}Options  > ${G}NETWORK rDNS & REVERSE IP (VHOSTS) II\n"
f_optionsNETDNS2; echo -e -n "\n${B}  ? ${D}  " ; read option_net_dns2
[[ $option_net_dns2 = "2" ]] || [[ $option_net_dns2 = "3" ]] && rdnsv6="true" || rdnsv6="false"
if [ $option_net_dns1 = "0" ]; then
[[ $option_net_dns2 = "0" ]] || [[ $option_net_dns2 = "2" ]] && net_dns="0"
[[ $option_net_dns2 = "1" ]] || [[ $option_net_dns2 = "3" ]] && net_dns="2"; else
[[ $option_net_dns2 = "0" ]] || [[ $option_net_dns2 = "2" ]] && net_dns="1"
[[ $option_net_dns2 = "1" ]] || [[ $option_net_dns2 = "3" ]] && net_dns="3"; fi; fi 
#************** - BANNERS / CVES - **************
if [ $option_enum =  "5" ]; then
option_scope="2"; psweep="false"
echo -e "\n${B}Options  > ${G}DETAILS III > Service Banners / CPEs & CVEs\n"
echo -e "${B} [1] ${G}API${B} >${D}  Banners         (hackertarget.com IP API max. size: /16)"
echo -e "${B} [2] ${G}API${B} >${D}  CPEs & Vulners  (Shodan API)"
echo -e "${B} [3]${D} BOTH"; echo -e -n "\n${B}  ? ${D}  " ; read option_netbanners; fi
#************** - SET TARGET - **************
if [ $option_enum !=  "1" ]; then
[[ $option_scope = "1" ]] && echo '' && f_Long && f_printLAN_V4
f_Long; f_setTARGET; fi
#************** - RUN OPTIONS  **************
[[ $option_enum = "1" ]] || option_detail="NA"
for x in $(cat $tempdir/targets.list); do
f_CLEANUP_FILES; is_net=$(echo $x | cut -s -d '/' -f 1)
[[ -n "$is_net" ]] && net_ip=$(echo $x | cut -s -d '/' -f 1 | tr -d ' ') || net_ip=$(echo $x | cut -s -d '-' -f 1 | tr -d ' ')
if [ -n "$net_ip" ] || [[ $net_ip =~ $REGEX_IP46 ]]; then
[[ $net_ip =~ $REGEX_IP4 ]] && net_out=$(echo $x | tr '/' '_') || net_out="NETv6"; f_BOGON "$x"
if [ $bogon = "TRUE" ] ; then
if [[ $net_ip =~ $REGEX_IP4 ]]; then
[[ $(${PATH_ipcalc} $net_ip | grep -c 'Private') -eq 1 ]] && net_type="private" || net_type="other"; else
net_type="other"; fi; else
net_type="public"; fi
if [ $option_enum = "1" ]; then
[[ $custom_file = "false" ]] && out="${outdir}/NET_REPORT.${net_out}.${file_date}.txt"
if [ $bogon = "TRUE" ]; then
echo ''; f_BOGON_HEADER "${x}"; echo ''; else
f_WHOIS_NET "${x}" | tee -a ${out}; fi; fi
#IPv4 options
if [[ $net_ip =~ $REGEX_IP4 ]]; then
if [ $option_enum = "3" ]; then
f_NET_HEADER "PING SWEEP  (NMAP)" | tee -a ${out}; f_PING_SWEEP "$x" | tee -a ${out}
elif [ $option_enum = "4" ]; then
if [ $net_dns = "1" ] || [ $net_dns = "3" ]; then
[[ $net_type = "private" ]] && nmap_ns="--system-dns"
[[ $net_dns = "1" ]] && [[ $custom_file = "false" ]] && out="${outdir}/NET_RDNS.${net_out}.${file_date}.txt"
[[ $net_dns = "3" ]] && [[ $custom_file = "false" ]] && out="${outdir}/NET_RDNS+REV_IP.${net_out}.${file_date}.txt"
f_NET_HEADER "rDNS" | tee -a ${out}; f_NET_RDNS "$x" | tee -a ${out}; fi
if [ $net_dns = "2" ] || [ $net_dns = "3" ]; then
[[ $net_dns = "2" ]] && [[ $custom_file = "false" ]] && out="${outdir}/REV_IP.${net_out}.${file_date}.txt"
[[ $net_dns = "3" ]] && [[ $custom_file = "false" ]] && out="${outdir}/NET_RDNS+REV_IP.${net_out}.${file_date}.txt"
f_NET_HEADER "REVERSE IP  (VHOSTS)" | tee -a ${out}; f_REV_IP "$x" | tee -a ${out}; fi
elif [ $option_enum = "5" ]; then
[[ $custom_file = "false" ]] && out="${outdir}/BANNERS.${net_out}_${file_date}.txt"
f_NET_HEADER "BANNERS" | tee -a ${out}
[[ $option_netbanners = "1" ]] || [[ $option_netbanners = "3" ]] && f_BANNERS "$x" | tee -a ${out}
[[ $option_netbanners = "3" ]] && echo '' | tee -a ${out}
[[ $option_netbanners = "1" ]] || [[ $option_netbanners = "3" ]] && f_NET_CVEs "$x" | tee -a ${out}
fi 
fi #end IPv4 options
else
echo -e "\nERROR: INVALID INPUT"; fi; done; fi
unset target_type; unset x; echo ''; fi; f_removeDir; f_Menu
;;
p) echo '' ; f_Long; f_options_P ;;
t|trace|traceroute) echo '' ; f_Long; f_options_T ;;
#************** WEB SERVER OPTIONS *******************
web|webserver|webservers|website|www)
f_makeNewDir; f_Long; f_optionsWWW; echo -e -n "\n${B}    ?${D}   "; read option_www
if ! [ $option_www = "b" ]; then
target_type="web"; domain_enum="false"; bgp_details="false"
[[ $option_www = "1" ]] && header_source="1"; echo ''; f_Long
#options_www 1 & 4 not allowed in non-target-connect mode
if [ $option_connect = "0" ] && [ $option_www = "1" ] || [ $option_www = "4" ]; then
echo -e "\n${R}Option not available in non-target-connect mode${D}\n"; else
#set target
f_setTARGET
if [ $option_www = "4" ]; then
option_starttls="0"; header_source="0"; echo -e "\n${B}Options  > ${G}Target SSL Port\n"
echo -e "${B} [1]${D} 443"; echo -e "${B} [2]${D} Customize port" ; echo -e -n "\n${B}  ? ${D}  " ; read option_sslports
if [ $option_sslports = "1" ] ; then
tls_port="443"; else
echo -e -n "\n${G}PORT${B} >  ${D}"; read input
tls_port=$(echo $input | sed 's/^ *//' | cut -d ',' -f 1 | cut -d ' ' -f 1); fi
echo -e "\n${B}Options  > ${G}Output\n"
echo -e "${B} [1]${D} Dump certs & print SSL info"
echo -e "${B} [2]${D} Quietly dump certs" ; echo -e -n "\n${B}  ? ${D}  " ; read option_dump
if [ $option_dump = "1" ]; then
echo -e "\n${B}Options  > ${G}testssl.sh\n"
echo -e "${B} [1]${D}  Run testssl.sh (SSL vulnerabilities, ciphers, revocation check)"
echo -e "${R} [0]${D}  SKIP"; echo -e -n "\n${B}   ?${D}  "; read option_testssl; else
quiet_dump="false"; option_testssl="0"; fi
elif [ $option_www = "2" ]; then
whois_full="true"
echo -e "\n${B} Options >${G} Website Info${D}\n"; echo -e "${B} [1] ${G}API${D} WhatWeb (via hackertarget.com)"
echo -e "${B} [2] ${G}API${D} urlscan.io"; echo -e "${B} [3]${D} BOTH"; echo -e -n "\n${B}  ? ${D}  " ; read option_webinfo
[[ $option_webinfo = "1" ]] || [[ $option_webinfo = "3" ]] && ww="true"
elif [ $option_www = "3" ]; then
if [ $option_connect = "0" ]; then
header_source="2"; else
echo -e "\n${B}Options  > ${G} Dump HTTP Headers ${B} > Source\n"
echo -e "${B} [1]${D}  cURL"; echo -e "${B} [2]${D}  hackertarget.com API"
echo -e -n "\n${B}  ? ${D}  " ; read header_source; fi; fi
#set curl user agent
if [ $option_connect != "0" ] && [ $header_source = "1" ]; then
error_code=6; echo -e "\n\n${B}Option > ${G}curl ${B}> ${G} User Agent\n"
echo -e "${B} [1]${D}  default"; echo -e "${B} [2]${D}  $ua_moz"; echo -e -n "\n${B}  ? ${D}  " ; read option_ua
[[ $option_ua = "2" ]] && curl_ua="-A $ua_moz" || curl_ua=""; fi
 #config option_www = 1
if [ $option_www = "1" ]; then
default_ttl=$(ping -c 1 127.0.0.1 | grep -so "ttl=.[0-9]${2,3}" | cut -s -d '=' -f 2 | tr -d ' '); whois_full="false"
option_starttls="0"; tls_port="443"; option_testssl="1"; send_ping="true"; nmap_ns="--dns-servers=9.9.9.9,1.1.1.1"
echo -e "\n${B} Options  > ${G} Website, Nmap Scan\n"
echo -e "${B} [1]${D}  Show more website related data"; echo -e "${B} [2]${D}  Nmap Port/Vulners Scan"
echo -e "${B} [3]${D}  BOTH"; echo -e "${R} [0]${D}  SKIP"; echo -e -n "\n${B}   ?${D}  "; read option_web_test
[[ $option_web_test = "1" ]] || [[ $option_web_test = "3" ]] && page_details="true" || page_details="false"
echo -e "\n${B}Options >${G} WhatWeb Website Data${B}\n"; echo -e "${B}[1]${D} hackertarget.com API"
echo -e "${B}[2]${D} Local App"; echo -e "${R}[0]${D} SKIP"; echo -e -n "\n${B}  ?${D}  "; read ww_source
[[ $ww_source = "0" ]] && ww="false" || ww="true"
if [ $option_web_test = "2" ] || [ $option_web_test = "3" ]; then
echo -e -n "\n${G}Run Nmap with elevated priviliges  ${B}[y] | [n]  ?${D}  " ; read option_root
declare -a nmap_array=(); declare -a port_array=(); echo -e "\n\n${B} Options  > ${G}Nmap\n"
echo -e "${B} [1]${D}  Safe Mode - (Uses Nmap Script from category 'safe' only)"
echo -e "${B} [2]${D}  Intrusive Mode  (using 'safe' & 'intrusive' skripts, skipping overly time consuming script scans)"
echo -e "${B} [3]${D}  Intrusive Mode - SLOW"
echo -e "${B} [4]${D}  Intrusive Mode - SLOW, all TCP Ports"
echo -e "${R} [0]${D}  SKIP"; echo -e -n "\n${B}  ?${D}   " ; read option_scripts
if [ $option_root = "y" ]; then
nmap_array+=(-sV -O --osscan-limit -Pn -R --resolve-all --open)
if [ $option_scripts = "2" ]; then
scripts="--script=${nse_web_safe},${nse_web1},${nse_root}"; script_args="--script-args http-methods.test-all"
elif [ $option_scripts = "3" ] || [ $option_scripts = "4" ]; then
scripts="--script=${nse_web_safe},${nse_web1},${nse_web2},${nse_root}"; script_args="--script-args http-methods.test-all"; else
scripts="--script=${nse_web_safe},${nse_root}"; script_args=''; fi
else
nmap_array+=(-sT -Pn -R --resolve-all --open)
if [ $option_scripts = "2" ]; then
scripts="--script=${nse_web_safe},${nse_web1}"; script_args="--script-args http-methods.test-all"
elif [ $option_scripts = "3" ] || [ $option_scripts = "4" ]; then
scripts="--script=${nse_web_safe},${nse_web1},${nse_web2}"; script_args="--script-args http-methods.test-all"; else
scripts="--script=${nse_web_safe}"; script_args=''; fi
fi #nmap privileges
if [ $option_scripts = "4" ]; then
option_ports="3"; ports="-p-"; else
echo -e "\n\n${B}Options  > ${G}Nmap Target Ports\n"; echo -e "${B} [1]${D}  Common web ports / ports found via Shodan (if applicable)"
echo -e "${B} [2]${D}  Customize ports"; echo -e -n "\n${B}  ? ${D}  " ; read option_ports
if [ $option_ports = "2" ]; then
echo -e -n "\n${B}Set     > Ports  ${D}- e.g. 636,989-995  ${B}>>${D} "; read ports_input; ports="-p $(echo $ports_input | tr -d ' ')"
fi; fi #nmap target ports
fi; fi #config option_www = 1
for x in $(cat $tempdir/targets.list | sort -uV); do
f_CLEANUP_FILES
#option_www = 4
if [ $option_www = "4" ]; then
[[ $quiet_dump = "false" ]] && out="${outdir}/SSL.${x}.$file_date.txt" && echo '' | tee -a ${out} || echo ''
f_CERT_INFO "$x" | tee -a ${out}; else
[[ $option_www = "1" ]] && out="${outdir}/WEBSERV_HealthCheck.${x}.${file_date}.txt"
[[ $option_www = "2" ]] && out="${outdir}/WEBSITE_OVERVIEW.${x}.${file_date}.txt"
[[ $option_www = "3" ]] && out="${outdir}/HTTP_HEADERS.${x}.txt"; echo '' | tee -a ${out}
dig @9.9.9.9 aaaa +short $x | grep ':' > $tempdir/ip6.list
dig @9.9.9.9 +short $x | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' > $tempdir/ip4.list
[[ $option_www = "1" ]] && f_wwwHEADER | tee -a ${out}
[[ $option_www = "2" ]] && f_HEADLINE "$x  WEBSITE SUMMARY | $file_date" | tee -a ${out}
[[ $option_www = "3" ]] && f_HEADLINE "$x" | tee -a ${out}
#option_www = 2
if [ $option_www = "2" ]; then
f_dnsCHAIN "$x" | tee -a ${out}; f_WHOIS_STATUS "$x" | tee -a ${out}
[[ $ww = "true" ]] && f_getWHATWEB "$x" && f_WHATWEB "$x" | tee -a ${out}
if [ $option_webinfo = "2" ] || [ $option_webinfo = "3" ]; then
f_HEADLINE2 "urlscan.io" |  tee -a ${out}
[[ $option_webinfo = "3" ]] && f_getURLSCAN "$target" || f_getURLSCAN "$x"
if [ -f $tempdir/ip4.list ]; then
for a in $(cat $tempdir/ip4.list | sort -uV); do
f_printURLSCAN "$a"; done | tee -a ${out}; fi
if [ -f $tempdir/ip6.list ]; then
for z in $(cat $tempdir/ip6.list | sort -uV); do
f_printURLSCAN "$z"; done | tee -a ${out}; fi; fi; else
if [ $option_www = "3" ]; then
[[ -f $tempdir/ip4.list ]] && echo '' && f_printADDR "$(cat $tempdir/ip4.list)" | tee -a ${out}
[[ -f $tempdir/ip6.list ]] && echo '' && f_printADDR "$(cat $tempdir/ip6.list)" | tee -a ${out}
#$option_www = 3 (header_source = hackertarget.com API)
[[ $header_source = "2" ]] && f_getHEADERS "${x}"; f_HEADERS "${x}" | tee -a ${out}; fi
#run option_www 1 & 3 in target-connect-mode
if [ $option_connect != "0" ]; then
if [ $option_www = "1" ] || [ $option_www = "3" ] && [ $header_source = "1" ]; then
declare -a st_array=() ; st_array+=(-sLkv); declare -a curl_array=() ; curl_array+=(-sLkv)
curl -s -f -L -k ${x} >/dev/null; f_Long
if [ $? = ${error_code} ]; then
echo -e "${R}$x  WEBSITE CONNECTION: FAILURE${D}\n"
echo -e "\n $x WEBSITE CONNECTION: FAILURE\n" >> ${out}; else
echo -e "$x  WEBSITE CONNECTION: ${G} SUCCESS${D}"
if [ $option_www = "3" ]; then
f_getHEADERS "$x"; echo '' | tee -a ${out}; f_HEADERS "$x" | tee -a ${out}; else #continue option_www = 1
f_Long >>  ${out}; echo -e "$x WEBSITE CONNECTION: SUCCESS" >> ${out}
echo '' > $tempdir/web_whois; f_WHOIS_STATUS "$x" >> $tempdir/web_whois
f_getPAGE_INFO "$x"; f_handshakeHEADER "$target" > $tempdir/hndshake
remote_ip=$(grep 'IP:' $tempdir/response | awk '{print $NF}' | tr -d ' ')
eff_url=$(grep 'URL:' $tempdir/response | awk '{print $NF}' | tr -d ' ')
target_host=$(echo $eff_url | sed 's/http:\/\///' | sed 's/https:\/\///' | cut -d '/' -f 1)
target_host4=$(f_RESOLVE_v4 "$target_host"); target_host6=$(f_RESOLVE_v6 "$target_host")
f_dnsCHAIN "$x" > $tempdir/web_dns
if [[ $target_host != $x ]]; then
f_dnsCHAIN "$target_host" >> $tempdir/web_dns; [[ -n "$target_host4" ]] && echo "$target_host4" >> $tempdir/ip4.list
[[ -n "$target_host6" ]] && echo "$target_host6" >> $tempdir/ip6.list
x_dom=$(f_getDOMAIN "$x"); target_dom=$(f_getDOMAIN "$target_host")
if [ $target_dom != $x_dom ]; then
echo -e "\n$x  WEBHOST DOMAIN:      $target_dom" | tee -a ${out}; echo ''; f_Long >> $tempdir/web_whois
f_WHOIS_STATUS "$target_dom" >> $tempdir/web_whois; fi; fi; f_Long | tee -a ${out}
[[ -f $tempdir/host_ipv4 ]] && cat $tempdir/host_ipv4 >> $tempdir/ip4.list
[[ -f $tempdir/host_ipv6 ]] && cat $tempdir/host_ipv6 >> $tempdir/ip6.list
[[ -f $tempdir/ip4.list ]] && sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n -u  $tempdir/ip4.list | tee $tempdir/v4_uniq > $tempdir/ips_all
[[ -f $tempdir/ip6.list ]] && grep ':' $tempdir/ip6.list | sort -uV | tee $tempdir/v6_uniq >> $tempdir/ips_all
[[ $(wc -w < $tempdir/v6_uniq) -gt 0 ]] && target6=$(cat $tempdir/v6_uniq)
[[ -f $tempdir/web_dns ]] && cat $tempdir/web_dns | tee -a ${out}
[[ -f $tempdir/web_whois ]] && f_Long | tee -a ${out} && cat $tempdir/web_whois | tee -a ${out}
if [[ $(wc -w < $tempdir/v4_uniq) -gt 0 ]]; then
target4=$(cat $tempdir/v4_uniq); f_Long | tee -a ${out}; f_whoisTABLE "$tempdir/v4_uniq"
cut -d '|' -f -5 $tempdir/whois_table.txt | sed '/^$/d' | sed '/NET NAME/G' | tee -a ${out}; fi
f_PAGE "$target" | tee -a ${out}
if [[ $( wc -w  < $tempdir/ips_all) -eq 1 ]]; then
f_printHANDSHAKE "${remote_ip}"; else
f_HEADLINE "SERVER INSTANCES" | tee -a ${out}
[[ -n $target_host4 ]] && f_printADDR "$target_host4" | tee -a ${out} 
[[ -n $target_host6 ]] && f_printADDR "$target_host6" | tee -a ${out}
f_Long | tee -a ${out}
if [ -n "$target_host4" ]; then
for a in $target_host4; do
echo -e "\n$a"; f_PING "$a"; echo '' | tee -a ${out}; done; fi 
if [ -n "$target_host6" ]; then
for z in $target_host6; do
echo -e "\n$z"; f_PING "$z"; echo '' | tee -a ${out}; done; fi 
if [ -n "$target_host4" ]; then
declare -a st_array=(); st_array+=(-s4Lkv)
for a in $target_host4; do
f_SERVER_INSTANCE "$a" | tee -a ${out}; f_printHANDSHAKE "$a"; unset a; done; fi
if [ -n "$target_host6" ]; then
declare -a st_array=(); st_array+=(-sLkv)
for z in $target_host6; do
f_SERVER_INSTANCE "$z" | tee -a ${out}; f_printHANDSHAKE "$z"; unset z; done; fi; fi
cat $tempdir/hndshake > ${outdir}/HANDSHAKES.${x}.${file_date}.txt
#****** HOSTS SUMMARY ******
echo -e "\n" | tee -a ${out}
if [ -n "$target6" ]; then
for z in $target6; do
echo ''; f_HOST_SHORT "$z"; echo ''; done | tee -a ${out}; fi
if [ -n "$target4" ]; then
for a in $target4; do
f_HOST_SHORT "$a"; echo ''; done | tee -a ${out}; fi
#****** NMAP ******
if [ $option_web_test = "2" ] || [ $option_web_test = "3" ]; then
f_Long; echo -e "\nRunning Nmap Scan ...\n"
if [ $option_ports = "1" ]; then
if [ -f $tempdir/detected_ports ]; then
ports_probe=$(cat $tempdir/detected_ports | sort -ug | sed 's/^/,T:/' | tr '[:space:]' ' ' | tr -d ' ' | sed 's/^\,//')
[[ -n "$ports_probe" ]] && echo -e "Scanning open ports found via Shodan - $ports_probe\n" && ports="-p $ports_probe" || ports="-p $ports_web"
fi; fi
[[ -n "$target4" ]] && option_ipv="v4" && opt_v6='' && f_RUN_NMAP "$target_host" | tee -a ${out}
[[ -n "$target6" ]] && option_ipv="v6" && opt_v6='-6' && f_RUN_NMAP "$target_host" | tee -a ${out}; fi
#****** SSL/TLS ******
f_CERT_INFO "$target_host" | tee -a ${out}
if [ $option_web_test = "2" ] || [ $option_web_test = "3" ]; then
echo '' | tee -a ${out}; f_HTML_COMMENTS "$x" | tee -a ${out}
[[ "$x" != "$target_host" ]] && f_HTML_COMMENTS "${target_host}" | tee -a ${out}; fi
if [ $option_web_test = "1" ] || [ $option_web_test = "3" ]; then
#****** Website Links & HTTP Headers
[[ -f $tempdir/print_ld ]] && cat $tempdir/print_ld | tee -a ${out}; fi
cat ${outdir}/HTTP_HEADERS.$x.txt  | fmt -s -w 100 | tee -a ${out}; fi  #option_www != 3
fi  #WEBSITE CONNECTION: FAILURE
fi  #option_www = 1 || option_www = 3 && header_source = 1
fi  #option_connect != 0
fi  #option_www != 2
fi  #option_www != 4
echo -e "\n" >> ${out}; done; unset target_type; unset x; echo ''
fi  #options_www 1 & 4 not allowed in non-target-connect mode
fi  #end option_www != b
f_removeDir; f_Menu
;;
#************** NMAP path-mtu.nse *******************
m1)
f_makeNewDir; f_Long; domain_enum="false"; target_type="hop"
[[ $option_connect = "0" ]] && f_targetCONNECT && f_Long
if ! [ $option_connect = "0" ] ; then
echo -e "${B}Options >${G} Nmap Path MTU${D}"; f_setTARGET
echo -e -n "\n${G}TARGET TCP/UPD PORTS ${D} - e.g. U:53,T:80  ${B}>>${D}  " ; read input
ports_mtu=$(echo $input | tr -d ' ')
if [ -n "$input" ]; then
f_TRACEROUTE_HEADER "NMAP PATH MTU" | tee -a ${out}
for x in $(cat $tempdir/targets.list); do
if [[ ${x} =~ ":" ]]; then
echo -e "\nNo IPv6 support\n"; else
f_PATH_MTU "$x" | tee -a ${out}; fi; done; fi; else
f_WARNING; fi; f_removeDir; f_Menu
;;
#************** NMAP - GENERAL PORT-/SERVICE-/VULNERABILITY SCAN OPTIONS *******************
p1)
f_makeNewDir; f_Long; target_type="nmap_target"; fw_enum="false"; [[ -f $tempdir/ports ]] && rm $tempdir/ports
[[ $option_connect = "0" ]] && f_targetCONNECT && f_Long
if ! [ $option_connect = "0" ]; then
declare -a nmap_array=()
echo -e "\n${B}NMAP PORT SCAN > \n\n${G}Expected input:${D}${bold} IP Address(es), Hostname(s), Address Range(s), Network(s) (CIDR) ${D}\n"
echo -e -n "\n${G}Run Nmap with elevated priviliges ${B}[y] | [n]  ?${D}  " ; read option_root
echo -e -n "\n${B}Options I > ${G}IP Mode ${B}>  [1]${D}  IPv4   ${B}|  [2]${D}  IPv6  ${B}?${D}  " ; read option_ipv
if [ $option_root = "y" ]; then
echo -e -n "\n${B}Options II > ${G}Protocols ${B}>  [1]${D} Scan TCP & UPD Ports ${B}| [2]${D} TCP only  ${B}?${D}  " ; read option_pro
echo -e "\n${B}Options III > ${G}Nmap Scan Types \n"
echo -e "${B} [1]${D} TCP Connect Scan"; echo -e "${B} [2]${D} SYN Scan"
echo -e -n "\n${B}  ?${D}  " ; read scan_type; else
option_pro="2"; scan_type="1"; script_type="x"; fi
echo -e "\n${B}Options IV > ${G}Ports \n"; echo -e "${B} [1]${D} Nmap Top 200 Ports"
echo -e "${B} [2]${D} Nmap Top 1000 Ports"; echo -e "${B} [3]${D} All (TCP) Ports"
if [ $option_pro = "2" ]; then
[[ $option_root = "n" ]] && message_root="(elevated privileges required for UDP scans)" || message_root=''
echo -e "${B} [4]${D} Enter TCP Port Numbers $message_root"; else
echo -e "${B} [4]${D} Enter Port Numbers and Protocols (TCP/UDP)"; fi
echo -e -n "\n${B}  ?${D}  "; read portChoice
[[ $portChoice = "3" ]] && option_pro="2"
if [ $portChoice = "1" ]; then
ports="--top-ports 200"
elif [ $portChoice = "2" ]; then
ports="--top-ports 1000"
elif [ $portChoice = "3" ]; then
ports="-p-"
elif [ $portChoice = "4" ]; then
if [ $option_pro = "1" ]; then
echo -e -n "\n${B}Ports  > ${D} e.g. T:22,U:53,T:80  ${B}>>${D}  " ; read port_input; else
echo -e -n "\n${B}Ports  > ${D} e.g. 22,25,80,443  ${B}>>${D}  " ; read port_input; fi
echo ",$port_input" > $tempdir/ports; fi
f_Long; f_setTARGET; if [ -f $tempdir/targets.list ]; then
echo -e -n "\n${B}Options V > ${G}Host Discovery ${B}>  [1]${D} Ping Targets (TCP,UDP,ICMP) ${B}| [0]${D} SKIP  ${B}?${D} " ; read option_ping
if [ $option_root = "n" ]; then
[[ $option_ping = "0" ]] && nmap_array+=(-Pn); nmap_array+=(-sT -R --open)
echo "banner,http-server-header,https-redirect,ssl-cert" > $tempdir/nse; else
echo "https-redirect,ssl-cert" >  $tempdir/nse
[[ $option_ping = "1" ]] && nmap_array+=(-PE -PP -PS22,25,80,113,443 -PA80,443,3389 -PU53,40125) || nmap_array+=(-Pn)
if [ $scan_type = "1" ]; then
[[ $option_pro = "1" ]] && nmap_array+=(-sS -sU) || nmap_array+=(-sS); else
[[ $option_pro = "1" ]] && nmap_array+=(-sT -sU) || nmap_array+=(-sT); fi
echo -e "\n${B}Options VI > ${G}Nmap Script & Version Scans \n"
[[ $scan_type = "1" ]] && echo -e "${B} [1]${D} Basic TCP Connect Scan" || echo -e "${B} [1]${D} Basic SYN Scan"
echo -e "${B} [2]${D} Service Version Scan"; echo -e "${B} [3]${D} Service- & OS Version Scan"
echo -e "${B} [4]${D} Service- & OS Version Scan, vulners.nse script (lists CVEs for identified services)"
echo -e "${B} [5]${D} Service- & OS Version Scan, Aggressive Script Scan (Option -A)"
echo -e -n "\n${B}  ?${D}  " ; read script_type
if [ $script_type != "1" ]; then
[[ $script_type = "4" ]] && echo ",unusual-port,vulners" >> $tempdir/nse || echo ",unusual-port" >> $tempdir/nse
[[ $script_type = "2" ]] && nmap_array+=(-sV --version-intensity 4 --open)
[[ $script_type = "3" ]] && nmap_array+=(-sV -O --osscan-limit --version-intensity 4 -R --open)
[[ $script_type = "4" ]] && nmap_array+=(-sV -O --osscan-limit --version-intensity 4 -R --open)
[[ $script_type = "5" ]] && nmap_array+=(-A -R --open); fi; fi
if [ $script_type = "5" ]; then
scripts=''; else
nse_scripts=$(cat $tempdir/nse | tr '[:space:]' ' ' | tr -d ' '; echo ''); scripts="--script=${nse_scripts}"; fi
[[ -f $tempdir/ports ]] && ports=$(cat $tempdir/ports | tr -d ' ')
[[ $report = "true" ]] && echo -e -n "\n${B}Output > ${G}OUTPUT - FILE NAME ${B}>>${D}  " && read filename && out="${outdir}/$filename.txt"
for x in $(cat $tempdir/targets.list | sort -uV) ; do
f_RUN_NMAP "${x}"; done | tee -a ${out}; fi; else
f_WARNING; fi; unset ports; unset nse_scripts; unset scripts; unset target_type; unset x; f_removeDir; f_Menu
;;
#************** NMAP PORT SCAN (via hackertarget.com IP Tools API) *******************
p2)
f_makeNewDir ; f_Long ; echo -e -n "\n${B}Nmap > Target >${D} IPv4 ADDRESS  >>${D}  " ; read target
out="${outdir}/PORTSCAN_HT.${target}.txt"; f_NMAP_HTAPI "${target}" | tee -a ${out}; echo -e "\n"; f_removeDir; f_Menu
;;
#*************** NMAP - FIREWALK / TCP FLAGS, FRAGMENTATION, SOURCE PORT SPOOFING *******************
p3)
f_makeNewDir ; f_Long ; target_type="nmap_target";  scripts=''; option_root="y"; fw_enum="true"
echo -e "\n${B}NMAP > ${G} Firewalk, TCP Flags, IP Protcol Scan\n${D}"
[[ $option_connect = "0" ]] && f_targetCONNECT && f_Long 
if ! [ $option_connect = "0" ]; then
echo -e "\n${B}Options  > ${G} Enumeration Methods\n"
echo -e "${B} [1]${D} Port Scan"; echo -e "${B} [2]${D} Firewalk"
echo -e "${B} [3]${D} BOTH"; echo -e "${R} [0]${D} QUIT";  echo -e -n "\n${B}  ?${D}  " ; read option_nmap1
if [ $option_nmap1 != "0" ]; then
declare -a nmap_array=(); declare -a nmap_array2=(); declare -a nmap_array3=(); declare -a port_array=()
nmap_array+=(-Pn --reason); nmap_array2+=(-Pn --reason); nmap_array3+=(-Pn --reason)
[[ $option_nmap1 = "2" ]] && snd_scan="false" && trd_scan="false"
echo -e "\n\n${B}Options  > ${G} Target Ports  >\n"
echo -e "${B} [1]${D} Top 20 Ports"
echo -e "${B} [2]${D} nmap Top 100 Ports"
echo -e "${B} [3]${D} nmap Top 500 Ports"
echo -e "${B} [4]${D} nmap Top 1000 Ports (default)"
echo -e "${B} [5]${D} Custom Port List"
echo -e -n "\n${B}  ?${D}  " ; read portChoice
if [ $portChoice = "5" ]; then
echo -e -n "\n${B}Ports  > ${D} e.g. 636,989-995  ${B}>>${D}  "; read port_input
ports="-p $(echo $port_input | tr -d ' ')"; else
[[ $portChoice = "1" ]] && ports="--top-ports 20"; [[ $portChoice = "2" ]] && ports="--top-ports 100"
[[ $portChoice = "3" ]] && ports="--top-ports 500"; [[ $portChoice = "4" ]] && ports="--top-ports 1000"; fi
if [ $option_nmap1 = "2" ] || [ $option_nmap1 = "3" ]; then
nmap_firewalk="true"; nmap_scan_type="FIREWALK"
echo -e "\n\n${B}Options  > ${G} Firewalk ${B}>${D} Set ${B}ammount of ports${D} to probe for each protocol (no port numbers!)\n"
echo -e -n "\n${B}Set   >  Num of ports ${D} - e.g. 5 ${B}>>${D}  " && read probes
echo -e "\n${B}Options  > ${G} Firewalk ${B} > Scan Type\n"
echo -e "${B} [1]${D} TCP Connect (-sT)"; echo -e "${B} [2]${D} SYN (Stealth Scan) (-sS)"
echo -e "${B} [3]${D} ACK (-sA)"; echo -e -n "\n${B}  ? ${D}  " ; read option_type
[[ $option_type = "1" ]] && scan_type="TCP CONNECT"; [[ $option_type = "2" ]] && scan_type="SYN"
[[ $option_type = "3" ]] && scan_type="ACK"; else
nmap_firewalk="false"; fi
if [ $option_nmap1 != "2" ]; then
[[ $nmap_firewalk = "true" ]] && f_Medium
echo -e "\n${B}Options  > ${G} Flag Scan ${B}> TCP Flags I\n"
echo -e "${B} [1]${D} SYN"; echo -e "${B} [2]${D} ACK"
echo -e "${B} [3]${D} SYN & ACK"; echo -e "\n${B} [4]${D} FIN"
echo -e "${B} [5]${D} FIN & ACK"; echo -e "${B} [6]${D} FIN, ACK & SYN"
echo -e "\n${B} [7]${D} WINDOW SCAN"; echo -e "${B} [8]${D} WINDOW SCAN & ACK"
echo -e "${B} [9]${D} WINDOW SCAN, ACK & SYN"
echo -e -n "\n${B}  ? ${D}  " ; read option_flag
if [ $option_flag = "2" ]; then
first_flag="Flag: ACK"; scan_flag="ACK"; nmap_array+=(-sA); snd_scan="false"
elif [ $option_flag = "3" ]; then
first_flag="SYN"; second_flag="ACK"; scan_flag="SYN & ACK"; nmap_array+=(-sS); nmap_array2+=(-sA); snd_scan="true"
elif [ $option_flag = "4" ]; then
first_flag="FIN"; scan_flag="FIN"; nmap_array+=(-sF); snd_scan="false"
elif [ $option_flag = "5" ]; then
first_flag="FIN"; second_flag="ACK"; scan_flag="FIN & ACK"; nmap_array+=(-sF); nmap_array2+=(-sA)
snd_scan="true"; trd_scan="false"
elif [ $option_flag = "6" ]; then
scan_flag="FIN, ACK & SYN"; snd_scan="true"; trd_scan="true"; first_flag="FIN"; second_flag="ACK"; third_flag="SYN"
nmap_array+=(-sF); nmap_array2+=(-sA); nmap_array3+=(-sS)
elif [ $option_flag = "7" ]; then
scan_flag="WINDOW SCAN"; first_flag="WINDOW SCAN"; nmap_array+=(-sW); snd_scan="false"
elif [ $option_flag = "8" ]; then
scan_flag="WINDOW SCAN & ACK"; first_flag="WINDOW SCAN"; second_flag="ACK"; snd_scan="true"; trd_scan="false"
nmap_array+=(-sW); nmap_array2+=(-sA)
elif [ $option_flag = "9" ]; then
scan_flag="TCP WINDOW SCAN, ACK & SYN"
first_flag="WINDOW SCAN"; second_flag="ACK"; third_flag="SYN"; snd_scan="true";  trd_scan="true"
nmap_array+=(-sW); nmap_array2+=(-sA); nmap_array3+=(-sS); else
first_flag="Flag: SYN"; scan_flag="SYN"; nmap_array+=(-sS); snd_scan="false"; fi
echo -e -n "\n${B}Options > ${B}>  [1]${D} Show additional options ${B}| ${R} [0]${D} SKIP  ${B}?${D}  " ; read option_add
if [ $option_add != "0" ]; then
echo -e "\n${B}Options  > ${G} Add Additional TCP Flags\n"; echo -e "${B} [1]${D} PSH (Push)"
echo -e "${B} [2]${D} URG"; echo -e "${B} [3]${D} ACK"; echo -e "${B} [4]${D} RST"
echo -e "${R} [0]${D} SKIP"; echo -e -n "\n${B}  ? ${D}  " ; read option_flag2
[[ $option_flag = "1" ]] && add_flag="/ PSH" && nmap_array+=(--scanflags PSH) && nmap_array2+=(--scanflags PSH) && nmap_array3+=(--scanflags PSH)
[[ $option_flag = "2" ]] && add_flag="/ URG" && nmap_array+=(--scanflags URG) && nmap_array2+=(--scanflags URG) && nmap_array3+=(--scanflags URG)
[[ $option_flag = "3" ]] && add_flag="/ ACK" && nmap_array+=(--scanflags ACK) && nmap_array2+=(--scanflags ACK) && nmap_array3+=(--scanflags ACK)
[[ $option_flag = "4" ]] && add_flag="/ RST" && nmap_array+=(--scanflags RST) && nmap_array2+=(--scanflags RST) && nmap_array3+=(--scanflags RST) 
echo -e "\n${B}Options > ${G} Source Port- & MAC Spoofing\n"; echo -e "${B} [1]${D}  Spoof source port"
echo -e "${B} [2]${D}  Spoof MAC address"; echo -e "${B} [3]${D}  BOTH"; echo -e "${R} [0]${D}  SKIP"; read option_spoof
if [ $option_spoof = "1" ] || [ $option_spoof = "3" ]; then
echo -e -n "\n${G}Source Port ${B}>>${D}  " && read sport
nmap_array+=(--source-port $sport); nmap_array2+=(--source-port $sport); nmap_array3+=(--source-port $sport); fi 
if [ $option_spoof = "2" ] || [ $option_spoof = "3" ]; then
nmap_array+=(--spoof-mac); nmap_array2+=(--spoof-mac); nmap_array3+=(--spoof-mac); fi
echo -e "\n${B}Option > ${G} Packet Length\n"; echo -e "${B} [1]${D}  Don't fragment (limits packet size to 8 bit)"
echo -e "${R} [0]${D}  SKIP"; echo -e -n "\n${B}  ? ${D}  " ; read option_len
[[ $option_len1 = "1" ]] && nmap_array+=(-f) && nmap_array2+=(-f) && nmap_array3+=(-f); fi; fi 
if [ $report = "true" ]; then 
echo -e -n "\n${G}Set   ${B}> ${D}OUTPUT - FILE NAME  ${B}>>${D}  "; read filename
out="${outdir}/$filename.${file_date}.txt"; fi
f_Long; f_setTARGET
f_HEADLINE "NMAP FWALL ENUM | $nmap_scan_type $scan_flag $add_flag | $(date -R)" | tee -a ${out}
for x in $(cat $tempdir/targets.list); do
f_RUN_NMAP "${x}" | tee -a ${out}
[[ $nmap_firewalk = "true" ]] && f_NMAP_FWALK "${x}" | tee -a ${out} ; done
fi; else
f_WARNING; fi; unset target_type; unset x; unset option_root; unset nmap_firewalk; unset first_flag; unset second_flag
unset third_flag; echo ''; f_removeDir; f_Menu
;;
#************** TRACEPATH *******************
t1|m2)
f_makeNewDir; f_Long; domain_enum="false"; target_type="hop"; file_date=$(date -I); f_get_IX_PFX; declare -a tpath_array=()
[[ $option_connect = "0" ]] && f_targetCONNECT && f_Long
if ! [ $option_connect = "0" ] ; then
echo -e "\n${B}TRACEPATH > ${G}Expected input:${D}${bold} IP Address(es), Hostname(s) ${D}\n"
echo -e -n "\n${B}Options  > ${G} IP Mode ${B} > [1]${D} IPv4 ${B}| [2]${D} IPv6 ${B}| [3]${D} Auto (default)  ${B}?${D}  " ; read IPvChoice
f_setTARGET; if [ $IPvChoice = "1" ] ; then
tpath_mode="IPV4"; tpath_array+=(-4)
elif [ $IPvChoice = "2" ]; then
tpath_mode="IPV6"; tpath_array+=(-6); else
tpath_mode="AUTO"; fi
echo -e "\n${B}Option   > ${G} Hop Details: ${B} Geolocation-, BGP- & RPKI- Data\n"
echo -e "${B} [1]${D} Show summary for each hop"
echo -e "${R} [0]${D} SKIP"; echo -e -n "\n${B}  ? ${D}  " ; read option_hop_details
if [ $option_hop_details = "0" ]; then
tpath_array+=(-b); out="${outdir}/ROUTES_TRACEPATH.${file_date}.txt"; else
tpath_array+=(-n); option_detail="1"; out="${outdir}/TRACEPATH_HOP_DETAILS.${file_date}.txt"; fi
echo -e -n "\n${B}Option   >${G} HOPS ${B}>${D} Max. number of Hops (default: 30) ${B}>>${D}  "; read hops; tpath_array+=(-m ${hops})
f_TRACEROUTE_HEADER "TRACEPATH (MODE: $tpath_mode)" | tee -a ${out}
for x in $(cat $tempdir/targets.list); do
unset hoplist; f_TRACEPATH "${x}"; hoplist=$(grep -E "[0-9]{1,2}:" $tempdir/trace | sed '/no reply/d' | awk '{print $2}')
if [ $option_hop_details = "1" ] && [ -n "$hoplist" ]; then
bgp_details="true"; for hop in $hoplist; do
hop_count=$(grep "${hop}" $tempdir/trace | grep -E -o "^[0-9]{1,2}:" | tr -d ':' | tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//')
rtt=$(grep "${hop}" $tempdir/trace | awk -F'ms' '{print $1}' | awk '{print $NF}' | tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//')
f_HOP "${hop}"; echo ''; f_CLEANUP_FILES; done; fi; done | tee -a ${out}; else
f_WARNING; echo ''; fi; unset target_type; unset x; f_removeDir; f_Menu
;;
#************** MTR (local installation) *******************
t2)
f_makeNewDir; f_Long; domain_enum="false"; target_type="hop"; file_date=$(date -I); f_get_IX_PFX; declare -a mtr_array=()
[[ $option_connect = "0" ]] && f_targetCONNECT && f_Long
if ! [ $option_connect = "0" ] ; then
echo -e "\n${B}MTR > ${G}Expected input:${D}${bold} IP Address(es), Hostname(s) ${D}\n"
echo -e -n "\n${B}Options  > ${G} MTR Mode ${B} > [1]${D} IPv4 ${B}| [2]${D} IPv6 ${B}| [3]${D} Auto (default)  ${B}?${D}  " ; read IPvChoice
if [ $IPvChoice = "1" ]; then
mtr_mode="IPV4"; mtr_array+=(-4 -z)
elif [ $IPvChoice = "2" ] ; then
mtr_mode="IPV6"; mtr_array+=(-6 -z); else
mtr_mode="AUTO"; mtr_array+=(-z); fi; f_setTARGET
echo -e "\n${B}Option   > ${G} Hop Details: ${B} Geolocation-, BGP-, RPKI- & -IPv4 only- IP Reputation Data\n"
echo -e "${B} [1]${D} Show details for each hop"
echo -e "${B} [2]${D} Show details including IP reputation data (IPv4 only)"
echo -e "${R} [0]${D} SKIP"; echo -e -n "\n${B}  ? ${D}  " ; read option_hop_details
if [ $option_hop_details = "1" ]; then
out="${outdir}/MTR_HOP_DETAILS.${file_date}.txt"; mtr_array+=(-n); else
mtr_array+=(-b); out="${outdir}/ROUTES_MTR.${file_date}.txt"; fi
echo -e -n "\n${B}Option   > ${G} Max. hops (default 30) ${B}>>${D}  " ; read hops; mtr_array+=(-m ${hops})
echo -e -n "\n${B}Option   > ${G} No of pings (e.g. 5) ${B}>>${D}  " ; read pingcount; mtr_array+=(-c ${pingcount})
echo -e "\n${B}Options  >${G}  Protocols\n"; echo -e "${B} [1]${D} ICMP (Type: Echo)"; echo -e "${B} [2]${D} TCP"
echo -e "${B} [3]${D} UDP"; echo -e "${B} [4]${D} SCTP (Stream Control Transmission Protocol)"; echo -e -n "\n${B}  ? ${D}  " ; read protocol_input
if ! [ $protocol_input = "1" ]; then
if [ $protocol_input = "3" ]; then
echo -e -n "\n${B}Option UDP >${G} Target Port (excl. 53)  ${B}>>${D}  " ; read tport_input; else
echo -e -n "\n${B}Option   >${G}  Target Port (e.g. 25)  ${B}>>${D}  " ; read tport_input; fi
[[ -n "$tport_input " ]] && tport=$(echo "$tport_input" | grep -sEo "[0-9]{1,5}")
if [ $protocol_input = "2" ]; then
mtr_array+=(--tcp -P $tport) ; mtr_protocol="TCP:$tport"
elif [ $protocol_input = "3" ]; then
mtr_array+=(--udp -P $tport); mtr_protocol="UDP:$tport"
elif [ $protocol_input = "4" ]; then
mtr_array+=(--sct -P $tport); mtr_protocol="SCTP:$tport"; fi ; else
mtr_protocol="ICMP"; fi
mtr_info="$mtr_mode, $mtr_protocol, PING COUNT: $pingcount"
f_TRACEROUTE_HEADER "MTR" | tee -a ${out}
f_HEADLINE2 "TARGETS\n" | tee -a ${out}; cat  $tempdir/targets.list | tee -a ${out}
for x in $(cat $tempdir/targets.list); do
unset hoplist; f_MTR "$x"
if [ $option_hop_details = "1" ] || [ $option_hop_details = "2" ]; then
bgp_details="true"
hoplist=$(sed 's/AS???/AS-/' $tempdir/mtr.txt | grep -E "^\s.[0-9]{1,2}\.|AS[0-9]{1,11}" | sed '/???/d' | sed '/^$/d' |
awk -F 'AS' '{print $2}' | awk -F' ' '{print $2}')
if [ -n "$hoplist" ]; then
for hop in $hoplist; do
unset hop_count; unset rtt
hop_count=$(sed 's/^ *//' $tempdir/mtr.txt | grep -E "^[0-9]{1,2}\." | grep -w $hop | cut -s -d '.' -f 1 |
tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//')
rtt=$(sed 's/AS???/AS-/' $tempdir/mtr.txt | grep 'AS' | sed '/???/d' | sed '/^$/d' | grep -w $hop | awk -F'%' '{print $NF}' | awk '{print $2}' |
tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//')
f_HOP "${hop}"; echo ''; f_CLEANUP_FILES; done
if [ $option_hop_details = "2" ]; then
f_HEADLINE "HOP | IP REPUTATION LOOKUP"
for a in $(echo "$hoplist" | grep -E grep -sEo "\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/32\b"); do
echo -e "\n$a\n"; f_IP_REPUTATION "$a"; done; fi
fi; fi; done | tee -a ${out}; unset tport; unset tport_input; unset x; else
f_WARNING; fi; unset target_type; unset x; f_removeDir; f_Menu
;;
t3)
#************** MTR (via hackertarget.com IP Tools API) *******************
f_makeNewDir; f_Long; file_date=$(date -I); target_type="hop"
echo -e -n "\n${G}MTR (API) ${B}> Target > ${G}IPV4 ADDRESS / HOSTNAME  ${B}>>${D}  " ; read target
echo -e "\n${B}Option   > ${G} Hop Details: ${B} Geolocation-, BGP-, RPKI- & IP Reputation Data)\n"
echo -e "${B} [1]${D} Show details for each hop"
echo -e "${B} [2]${D} Show details for each hop  (incl. IPv4 blocklist check)"
echo -e "${R} [0]${D} SKIP"; echo -e -n "\n${B}  ? ${D}  " ; read option_hop_details
if [ $option_hop_details = "0" ]; then
out="${outdir}/ROUTES_MTR.API.${file_date}.txt"; else
domain_enum="false"; option_detail="1"; f_get_IX_PFX; out="${outdir}/MTR.API_HOP_DETAILS.${file_date}.txt"; fi
f_TRACEROUTE_HEADER "MTR (SOURCE: hackertarget.com IP Tools API)" | tee -a ${out}
f_MTR_HTAPI "${target}" | tee -a ${out}
hoplist=$(grep '|' $tempdir/mtr_ht | grep -v '???' | awk -F'--' '{print $2}' | sed '1,1d' | awk -F' ' '{print $1}')
if ! [ $option_hop_details = "0" ] && [ -n "$hoplist" ]; then
for i in $hoplist; do
hop_count=$(grep "${i}" $tempdir/mtr_ht | awk -F'|' '{print $1}' | tr -d '.' | tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//')
if ! [[ ${i} =~ $REGEX_IP4 ]] ; then
a=$(dig @anycast.censurfridns.dk a +short $i | egrep -s -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'); else
a="$i"; fi
if [[ ${a} =~ $REGEX_IP4 ]]; then
f_HOP "${a}"; echo ''; f_CLEANUP_FILES; fi; done | tee -a ${out}; fi
unset target_type; unset x; f_removeDir; f_Menu
;;
t4)
f_makeNewDir; f_Long; domain_enum="false"; option_detail="1"; target_type="hop"; declare -a trace_array=()
[[ $option_connect = "0" ]] && f_targetCONNECT && f_Long
if ! [ $option_connect = "0" ]; then
echo -e "\n${B}NMAP GEOTRACE > ${G}Expected input:${D}${bold} IP Address(es), Hostname(s) ${D}\n"
echo -e -n "\n${B}Options  > ${G} IP Vers. ${B} > [1]${D} IPV4 MODE  ${B}| [2]${D}  IPV6 MODE  ${B}?${D}  " ; read IPvChoice
[[ $IPvChoice = "2" ]] && trace_array+=(-6)
trace_array+=(-sn); f_setTARGET; echo -e "\n${B}Option   > ${G} Hop Details: ${B} Geolocation-, BGP- & RPKI-DATA\n"
echo -e "${B} [1]${D} Show details for each hop"
echo -e "${R} [0]${D} SKIP"; echo -e -n "\n${B}  ? ${D}  " ; read option_hop_details
if [ $option_hop_details = "0" ]; then
trace_array+=(-R --resolve-all); out="${outdir}/ROUTES_NMAP.${file_date}.txt"; else
trace_array+=(-n); option_detail="1"; out="${outdir}/NMAP_HOP_DETAILS.${file_date}.txt"; fi
echo -e "\n${B}Options  > ${G}Protocols${B} > ${G}TCP & UDP\n"
echo -e "${B} [1]${D} TCP (ACK)"; echo -e "${B} [2]${D} UDP"
echo -e "${B} [3]${D} BOTH" ; echo -e "${R} [0]${D} SKIP"
echo -e -n "\n${B}  ? ${D}  " ; read option_proto1
[[ $option_proto1 = "1" ]] || [[ $option_proto1 = "3" ]] &&
echo -e -n "\n${B}Ports   > ${G} TCP ACK ${B}> - e.g. 25,80,135  ${B}>>${D} " && read tcp_ports && trace_array+=(-PA${tcp_ports})
[[ $option_proto1 = "2" ]] || [[ $option_proto1 = "3" ]] &&
echo -e -n "\n${B}Ports   > ${G} UDP ${B}> - e.g. 25,80,135  ${B}>>${D} " && read udp_ports && trace_array+=(-PU${udp_ports})
echo -e "\n${B}Option  > ${B} > Protocols${B} > ${G}ICMP & IP PROTOCOL SCAN${D}\n"
echo -e "(To provoke an ICMP 'protocol unreachable' response select option [2])\n"
echo -e "${B} [1]${D} ICMP Echo"; echo -e "${B} [2]${D} IP Protocol Scan (sends multiple ICMP, IGMP & IP-in-IP packets)"
echo -e "${R} [0]${D} SKIP"; echo -e -n "\n${B}  ? ${D}  " ; read option_proto2
[[ $option_proto2 = "1" ]] || [[ $option_proto2 = "3" ]] && trace_array+=(-PE)
[[ $option_proto2 = "2" ]] || [[ $option_proto2 = "3" ]] && trace_array+=(-PO)
f_TRACEROUTE_HEADER "NMAP GEO TRACEROUTE" | tee -a ${out}
for x in $(cat $tempdir/targets.list); do
f_nmapGEOTRACE "${x}"
hoplist=$(sed -n '/GEOLOCATION/,$p' $tempdir/geotrace | sed '/GEOLOCATION/d' | sed '/^$/d' | sed '1,1d' | awk '{print $3}' |  tr -d ' ')
if ! [ $option_hop_details = "0" ] && [ -n "$hoplist" ]; then
echo -e " \n\n$hoplist"
for i in $hoplist; do
if [[ $i =~ $REGEX_IP4 ]] || [[ ${i} =~ ":" ]]; then
hop="$i"; else
if [ $IPvChoice = "1" ]; then
hop=$(dig +short $i | egrep -s -o -m 1 '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'); else
hop=$(dig +short aaaa $i | grep -m 1 ':'); fi; fi
rtt=$(sed -n '/GEOLOCATION/,$p' $tempdir/geotrace | grep -w "${hop}" | awk '{print $2}' | tr -d ' ')
f_HOP "${hop}"; echo ''; f_CLEANUP_FILES; done; fi; done | tee -a ${out}; else
f_WARNING; fi; unset target_type; unset x; f_removeDir; f_Menu
;;
#************** DUBLIN TRACEROUTE *******************
t5)
f_makeNewDir; f_Long; domain_enum="false"; file_date=$(date -I); target_type="hop"
[[ $option_connect = "0" ]] && f_targetCONNECT && f_Long
if ! [ $option_connect = "0" ]; then
echo -e "\n${B}DUBLIN TRACEROUTE > ${G}Expected input:${D}${bold} IPv4 Address(es), Hostname(s) ${D}\n"
f_setTARGET; for x in $(cat $tempdir/targets.list); do
out="${outdir}/ROUTES.DUBLIN_T.${x}.txt"
f_TRACEROUTE_HEADER "DUBLIN TRACEROUTE | $x"; f_dnsCHAIN "$x"
if ! [[ ${x} =~ $REGEX_IP4 ]] ; then
for a in $(dig +short $x | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'); do
sudo ${PATH_dublin_t} -n 15 $a > $tempdir/d_t
echo ''; f_HEADLINE2 "$x ($a)\n"
sed -n '/Traceroute from/,/Saved JSON/p' $tempdir/d_t | sed '/==/{x;p;x;G}' | sed 's/NAT ID:/\n     NAT ID:/g' |
sed '/flow hash/G' | sed '/*/G' | sed "/Saved JSON file/{x;p;x;}"; done; else
sudo ${PATH_dublin_t} -n 15 $x > $tempdir/d_t
echo ''; f_HEADLINE2 "$x\n"
sed -n '/Traceroute from/,/Saved JSON/p' $tempdir/d_t | sed '/==/{x;p;x;G}' | sed 's/NAT ID:/\n     NAT ID:/g' |
sed '/flow hash/G' | sed '/*/G' | sed "/Saved JSON file/{x;p;x;}"; fi; done | tee -a ${out}
echo -e "\n"; unset target_type; unset a; unset x; echo ''; else
f_WARNING; fi; f_removeDir; f_Menu
;;
#************** AFRINIC, APNIC & RIPE INVERSE SEARCHES  *******************
w1)
f_makeNewDir; f_Long; target_type="other" ; option_detail="1"; domain_enum="false"; orgs=''; orgs_other=''
echo -e "\n${B}Options  > Sources > whois Servers >\n"
echo -e "${B} [1]${D}  RIPE" ; echo -e "${B} [2]${D}  AFRINIC"
echo -e "${B} [3]${D}  APNIC"; echo -e "\n${B} [b]${D}  Back to the Global Options ${G}Menu${D}"
echo -e -n "\n${B}   ?${D}  " ; read reg_choice
if [ $reg_choice != "b" ]; then 
if [ $reg_choice = "2" ] ; then
rir="afrinic"; iregistry="AFRINIC" ; rir_server="whois.afrinic.net"
elif [ $reg_choice = "3" ] ; then
rir="apnic"; iregistry="APNIC" ; rir_server="whois.apnic.net" ; else
rir="ripe"; iregistry="RIPE" ; rir_server="whois.ripe.net" ; fi
f_Long ; echo -e "\n${B}Expected Input${D} - ${G}ObjectType;SearchTerm${D}  -  e.g.  admin-c;JohnDoeXY-RIPE\n"
echo -e -n "\n${G}Target  ${B}> [1]${D} Single entry ${B}| [2]${D} Read from file  ${B}?${D}  " ; read option_target
if [ $option_target = "2" ] ; then
echo -e -n "\n${B}Target  > ${G}PATH TO FILE ${D}e.g. ./objects.list  ${B}>>${D}   " ; read input
f_prepareINPUT "$input" > $tempdir/targets; else
echo -e -n "\n${B}Target  > ${G}SEARCH TERM  ${B}>>${D} " ; read input
echo "$input" > $tempdir/targets_tmp; f_prepareINPUT "$tempdir/targets_tmp" > $tempdir/targets; fi
if [ $option_target = "2" ] && [ $report = "true" ] ; then
echo -e -n "\n${B}Output  > ${G}OUTPUT - FILE NAME  ${B}>>${D}  " ; read filename ; fi
headl="$tempdir/headline"; echo -e "\n"
echo -e "\n" > ${headl}; f_Long | tee -a ${headl}; echo -e "WHOIS | OBJECT & INVERSE SEARCHES  [$rir_server] ($file_date)" | tee -a ${headl}
f_Long | tee -a ${headl}; echo -e "\nSearching...\n" | tee -a ${headl}; cat $tempdir/targets | tee -a ${headl}
echo '' | tee -a ${headl}
for t in $(cat $tempdir/targets) ; do
x=$(echo $t | grep -E "*.;.*")
query_type=$(echo "$x" | cut -d ';' -f 1) ; obj=$(echo "$x" | cut -d ';' -f 2)
if [ $option_target = "1" ] ; then
filename=$(echo $x | cut -d ';' -f 2- | tr -d ' '); fi
if [ $query_type = "org" ] ; then
echo "$obj" | tr -d ' ' >> $tempdir/orgs.list
elif [ $query_type = "admin-c" ] ; then
echo "$obj" | tr -d ' ' | tee -a $tempdir/objects.list >> $tempdir/admins1_raw
elif [ $query_type = "tech-c" ] ; then
echo "$obj" | tr -d ' ' | tee -a $tempdir/objects.list >> $tempdir/admins1_raw
elif [ $query_type = "abuse-c" ] ; then
echo "$obj" | tr -d ' ' | tee -a $tempdir/objects.list >> $tempdir/admins1_raw
elif [ $query_type = "mnt-by" ] ; then
echo "$obj" | tr -d ' ' | tee -a $tempdir/objects.list >> $tempdir/mntners
elif [ $query_type = "mnt-lower" ] ; then
echo "$obj" | tr -d ' ' | tee -a $tempdir/objects.list >> $tempdir/mntners
elif [ $query_type = "origin" ] ; then
echo "$obj" | tr -d ' ' | tee -a $tempdir/objects.list >> $tempdir/asns.list; else
echo "$obj" >> $tempdir/objects.list; fi
timeout 10 whois -h ${rir_server} -- "--no-personal -i ${query_type} ${obj}" >> $tempdir/whois_temp
f_whoisFORMAT "$tempdir/whois_temp" >> $tempdir/who1
timeout 10 whois -h ${rir_server} -- "--no-personal ${obj}" >> $tempdir/whois_temp2
f_whoisFORMAT "$tempdir/whois_temp2" >> $tempdir/who2; done
[[ -f $tempdir/who1 ]] && cat $tempdir/who1 > $tempdir/full_output; [[ -f $tempdir/who2 ]] && cat $tempdir/who2 >> $tempdir/full_output
netcount=$(grep -sEc "^netname:" $tempdir/whois_temp); netcount4=$(grep -sEc "^inetnum:" $tempdir/whois_temp)
netcount6=$(grep -sEc "^inet6num:" $tempdir/whois_temp)
[[ -f $tempdir/admins1_raw ]] && cat $tempdir/admins1_raw | sort -u > $tempdir/admins1
grep -E "^abuse-c:|^admin-c:|^tech-c:" $tempdir/full_output | awk '{print $NF}' | sort -u > $tempdir/admins2
[[ -f $tempdir/admins1 ]] && diff --suppress-common-lines --ignore-all-space $tempdir/admins1 $tempdir/admins2 | grep '>' |
cut -d ' ' -f 2 | sed 's/^ *//' > $tempdir/admins_other
grep -E "^org:" $tempdir/full_output | awk '{print $NF}' > $tempdir/orgs.list
grep -E "^aut-num:|^origin:" $tempdir/full_output | awk '{print $NF}' | sed 's/AS//g' >> $tempdir/asns.list
asns=$(cat $tempdir/asns.list | sort -ug)
if [ -n "$asns" ]; then
f_HEADLINE "AUTONOMOUS SYSTEMS" | tee -a ${out}
for a in $asns; do
f_AS_SHORT "${a}"; echo ''; done | tee -a ${out}; fi
if [ -f $tempdir/orgs.list ]; then
f_HEADLINE "ORGANISATIONS" | tee -a ${out}
for oid in $(sort -u $tempdir/orgs.list); do
timeout 10 whois -h ${rir_server} -- "--no-personal $oid" > $tempdir/whois_org
echo ''; f_ORG_SHORT "$tempdir/whois_org"; f_getRIRObjects "$tempdir/whois_org"; done | tee -a ${out}
for oid in $(sort -u $tempdir/orgs.list); do
echo '' ; f_netBLOCKS "${oid}" ; done | tee -a ${out}; fi
#**** NETWORKS ****
if [[ $netcount -gt 0 ]]; then
grep -sEav "^remarks:|RIPE-NCC-HM-MNT|RIPE-NCC-LEGACY-MNT" $tempdir/whois_temp | sed '/inetnum:/{x;p;x;}' |
sed '/inet6num:/{x;p;x;}' | sed -e '/./{H;$!d;}' -e 'x;/netname:/!d' > $tempdir/nets_inverse
if [[ $netcount6 -gt 0 ]]; then
f_HEADLINE "NETWORKS - IPV6" | tee -a ${out}
sed -e '/./{H;$!d;}' -e 'x;/inet6num:/!d' $tempdir/nets_inverse > $tempdir/inets6
grep -sEa "^inet6num:|^netname:|^country:|^org:|^source:" $tempdir/inets6 |
sed '/inet6num:/{x;p;x;}' | sed '/source:/G' > $tempdir/inets6_2
grep -sEa "^inet6num:|^descr:|^source:" $tempdir/inets6 | sed '/inet6num:/{x;p;x;}' | sed '/source:/G' > $tempdir/inets6_3
inet6nums=$(grep -sE "^inet6num:" $tempdir/nets_inverse | awk '{print $NF}' | tr -d ' ' | sort -uV)
for z in $inet6nums; do
echo -e "\n\n$z\n"
grep -sEa -m 1 -A 4 "${z}" $tempdir/inets6_2 | grep -sEa -m 2 "^netname:|^country:" | sed '/^country:/i \|' | cut -d ':' -f 2- |
sed 's/^[ \t]*//;s/[ \t]*$//' > $tempdir/v6_tmp; grep -sEa -m 1 -A 4 "${z}" $tempdir/inets6_2 | grep -sEa -m 1 "^org:" |
sed '/^org:/i \|' | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' >> $tempdir/v6_tmp; grep -sEa -m 1 -A 1 "${z}" $tempdir/inets6_3 |
grep 'descr:' | sed '/^descr:/i \|' | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' >> $tempdir/v6_tmp
sed 's/^[ \t]*//;s/[ \t]*$//' $tempdir/v6_tmp | tr '[:space:]' ' '; echo ''; done | tee -a ${out}; echo '' | tee -a ${out}; fi
if [[ $netcount4 -gt 0 ]]; then
f_HEADLINE "NETWORKS - IPV4" | tee -a ${out}
sed -e '/./{H;$!d;}' -e 'x;/inetnum:/!d' $tempdir/nets_inverse > $tempdir/inets4
grep -sEa "^inetnum:|^netname:|^country:|^org:|^source:" $tempdir/inets4 | sed '/inetnum:/{x;p;x;}' | sed '/source:/G' > $tempdir/inets4_2
grep -sEa "^inetnum:|^descr:|^source:" $tempdir/inets4 | sed '/inetnum:/{x;p;x;}' | sed '/source:/G' > $tempdir/inets4_3
grep -sEa "^inetnum:" $tempdir/nets_inverse | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | tr -d ' ' | sort -u |
sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n > $tempdir/inums1
for a in $(cat $tempdir/inums1); do
inum=$(echo $a | sed 's/-/ - /'); inum_cidr=$(ipcalc ${a} | sed '/deaggregate/d' | sed '/^$/d' | tr '[:space:]' ' ')
echo -e "\n\n$inum\n" >> $tempdir/netranges
grep -sEa -m 1 -A 4 "${inum}" $tempdir/inets4_2 | grep -sEa -m 2 "^netname:|^country:" | sed '/^country:/i \|' | cut -d ':' -f 2- |
sed 's/^[ \t]*//;s/[ \t]*$//' > $tempdir/v4_tmp; grep -sEa -m 1 -A 4 "${inum}" $tempdir/inets4_2 | grep -sEa -m 1 "^org:" |
sed '/^org:/i \|' | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' >> $tempdir/v4_tmp; grep -sEa -m 1 -A 1 "${inum}" $tempdir/inets4_3 |
grep 'descr:' | sed '/^descr:/i \|' | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' >> $tempdir/v4_tmp
[[ $(echo "$inum_cidr" | wc -w) -lt 3 ]] && echo -e "| $inum_cidr" >> $tempdir/v4_tmp
sed 's/^[ \t]*//;s/[ \t]*$//' $tempdir/v4_tmp | tr '[:space:]' ' ' >> $tempdir/netranges
echo '' >> $tempdir/netranges; ipcalc ${inum} | sed '/deaggregate/d' | sed '/^$/d' >> $tempdir/cidr; done
cat $tempdir/netranges | tee -a ${out}; rm $tempdir/netranges; echo '' | tee -a ${out}
if [[ $(cat $tempdir/cidr | wc -w) -gt 2 ]]; then
echo -e "_______________________________________\n"  | tee -a ${out}
cat $tempdir/cidr | tr -d ' '  | sort -t / -k 2,2n | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n -u -V | tr '[:space:]' ' ' | sed 's/ /  /g' |
sed 's/^ *//' | fmt -s -w 40 | tee -a ${out} ; else
echo -e "\n________________\n" | tee -a ${out}; cat $tempdir/cidr | tr -d ' '  |
sort -t / -k 2,2n | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n -u -V | tee -a ${out}; fi; fi; fi
#**** ROUTE OBJECTS ****
route_obj4=$(sed -e '/./{H;$!d;}' -e 'x;/route:/!d' $tempdir/full_output | grep -E "^route:|^origin" | grep -E -B 1 "^origin:" |
sed '/--/d' | sed '/^$/d')
route_obj6=$(sed -e '/./{H;$!d;}' -e 'x;/route6:/!d' $tempdir/full_output | grep -E "^route6:|^origin" | grep -E -B 1 "^origin:" |
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
[[ -n "$origin6" ]] && echo -e "\n" | tee -a ${out}
echo -e "\nRoutes (IPv4)\n_____________" | tee -a ${out}; echo "$route_obj4" | sed 's/as/AS/g' > $tempdir/route_obj4
origin4=$(grep -E "^origin:" $tempdir/route_obj4 | cut -d ':' -f 2- | sed 's/^ *//' |  tr -d ' ' | sort -u -f -V)
for o in $origin4; do
echo -e "\n\n$o\n" | sed 's/AS/AS /g'; grep -E -B 1 "${o}" $tempdir/route_obj4 | sed '/--/d' | sed '/^$/d' |
grep -E -v "^origin:" | cut -d ' ' -f 2- | sed 's/^ *//' | tr -d ' ' | sort -u -V >> $tempdir/routes4
cat $tempdir/routes4 | tr -d ' '  | sort -t / -k 2,2n | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n -u -V
rm $tempdir/routes4; done | tee -a ${out}; fi
#**** ABUSE CONTACTS / POCs ****
echo '' | tee -a ${out}; f_HEADLINE "POINTS OF CONTACT" | tee -a ${out}
abuse_mb=$(grep -sEoa "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $tempdir/full_output | sort -u)
[[ -n "$abuse_mb" ]] && echo -e "ABUSE MAIL\n\n$abuse_mb\n" | tee -a ${out}
if [ -f $tempdir/admins1 ]; then
[[ -n "$abuse_mb" ]] && f_Long | tee -a ${out}; echo -e "\nCONTACTS (QUERY)" | tee -a ${out}
for ac in $(cat $tempdir/admins1 | sort -u); do
echo -e "\n\n$ac\n\n"; f_ADMIN_C "$ac"; echo ''; done | tee -a ${out}; fi
if [ -f $tempdir/admins_other ] && [ $(wc -w < $tempdir/admins_other) -gt 0 ]; then
echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo -e "\nCONTACTS (OTHER)" | tee -a ${out}
for aco in $(sort -u $tempdir/admins_other | sort -u); do
echo -e "\n\n$aco\n\n"; f_ADMIN_C "$aco"; echo ''; done | tee -a ${out}; fi
cat $headl >> ${outdir}/WHOIS.${filename}.txt ; cat ${out} >> ${outdir}/WHOIS.${filename}.txt; fi
echo ''; unset target_type; unset x; f_Menu
;;
w2)
#************** AFRINIC, APNIC & RIPE POC SEARCHES  *******************
f_makeNewDir; f_Long; target_type="whois_target"; domain_enum="false"; unset rir
echo -e "${B}\nWHOIS POC SEARCH > ${G} Expected input:${D}\n"
echo -e "${bold}Org-IDs, NIC-HDLs, name servers, person-/role-/org names${D}\n"
echo -e "Use option ${G}x)${D} to search for network names\n"; f_Long
echo -e "\n${B}Options  > Sources > RIR whois Servers >\n"
echo -e "${B} [1]${D}  RIPE"; echo -e "${B} [2]${D}  AFRINIC"; echo -e "${B} [3]${D}  APNIC"
echo -e -n "\n${B}   ?${D}  "; read option_rir
[[ $option_rir = "1" ]] && rir="ripe"; [[ $option_rir = "2" ]] && rir="afrinic"; [[ $option_rir = "3" ]] && rir="apnic"
if [ -n "$rir" ]; then
f_setTARGET
echo -e "\n${B}Options  > ${G}PoC Details\n\n${R}(CAUTION: Excessive queries for personal details may result in blocked access to RIR databases)\n"
echo -e "${B} [1]${D} Limit results for personal data"
echo -e "${B} [2]${D} Look up Full Contact Details (not recommended if searching for names rather than handles)"
echo -e -n "\n${B}   ?${D}  " ; read option_poc
if [ $report = "true" ]; then
echo -e "\n${B}Options  > ${G}Output File\n"
echo -e "${B} [1]${D} Set custom  name for output file"
echo -e "${B} [2]${D} Use default (target_input.current_date.txt)"
echo -e -n "\n${B}   ?${D}  " ; read option_filename
if [ $option_filename = "1" ]; then
echo -e -n "\n${B}Output  > ${G}OUTPUT - FILE NAME  ${B}>>${D}  " ; read filename
out="${outdir}/filename.txt"; fi; fi
for x in $(cat $tempdir/targets.list | sort -uV); do
echo ''; trimmed=$(echo $x | cut -d '/' -f 1 | cut -d '-' -f 1 | tr -d ' ')
if [[ $trimmed =~ $REGEX_IP46 ]]; then
echo -e "\nTo query IP or Network Addresses use options 1), n) oder ip)\n"; else
unset admins_other; unset orgs_other; unset netcount; unset netcount4; unset netcount6; unset nets4 
f_CLEANUP_FILES; [[ -f $tempdir/org_ids ]] && rm $tempdir/org_ids; [[ -f $tempdir/net_admins ]] && rm $tempdir/net_admins
[[ -f $tempdir/net_orgs ]] && rm $tempdir/net_orgs; [[ $option_filename = "2" ]] && out="${outdir}/${x}.${file_date}.txt"
if [ $option_poc = "2" ]; then
timeout 10 whois -h whois.$rir.net -- "-B ${x}" | sed '/RIPE-NCC-LEGACY-MNT/d' | sed '/RIPE-NCC-HM-MNT/d' > $tempdir/whois
netcount4=$(grep -sEc "^inetnum:" $tempdir/whois); netcount6=$(grep -sEc "^inet6num" $tempdir/whois)
netcount=$(grep -sEc "^netname" $tempdir/whois)
grep -sEa "^organisation:" $tempdir/whois | awk '{print $NF}' | tr -d ' ' | sort -u > $tempdir/net_orgs
grep -sEa "^org:" $tempdir/whois | awk '{print $NF}' | tr -d ' ' | sort -u > $tempdir/nh_orgs
f_POC "$tempdir/whois";
if [[ $netcount -gt 0 ]]; then
f_getNETS "$tempdir/whois" > $tempdir/whois_nets 
grep -sEa "^nic-hdl:" $tempdir/whois | awk '{print $NF}' | tr -d ' ' | sort -u | sed '/^$/d' > $tempdir/nh
grep -sEa "^admin-c:" $tempdir/whois_nets | awk '{print $NF}' | tr -d ' ' | sort -u | sed '/^$/d' > $tempdir/adm
grep -sEa "^organisation:" $tempdir/whois | awk '{print $NF}' | tr -d ' ' | sort -u > $tempdir/orgs
grep -sEa "^org:" $tempdir/whois | awk '{print $NF}' | tr -d ' ' | sort -u > $tempdir/net_orgs
 if [[ $netcount4 -gt 0 ]]; then
nets4=$(grep -E "^inetnum:" $tempdir/nets | cut -d ':' -f 2- | sed 's/^ *//' | egrep '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' |
tr -d ' '); f_getNETS4 "$tempdir/whois" > $tempdir/nets4_tmp; f_printNETS "$tempdir/nets4_tmp" > $tempdir/nets4; fi
if [[ $netcount6 -gt 0 ]]; then
f_getNETS6 "$tempdir/whois" > $tempdir/nets4_tmp; f_printNETS "$tempdir/nets6_tmp" > $tempdir/nets6; fi; fi
else 
timeout 10 whois -h whois.$rir.net -- "-F -r ${x}"  | tr -d '*' | sed 's/^ *//' | sed '/RIPE-NCC-LEGACY-MNT/d' |
sed '/RIPE-NCC-HM-MNT/d' > $tempdir/whois_temp
if [ -f $tempdir/whois_temp ]; then
netcount4=$(grep -sEc "^in:" $tempdir/whois_temp); netcount6=$(grep -sEc "^i6:" $tempdir/whois_temp)
netcount=$(grep -sEc "^in:|^i6:" $tempdir/whois_temp); poc_count=$(grep -sEc "^it:|^mt:|^oa|^pn:|^ro:" $tempdir/whois_temp)
if [[ $netcount -gt 0 ]]; then
grep -sEa "^ac:" $tempdir/whois_temp | awk '{print $NF}' | tr -d ' ' | sort -u > $tempdir/adm
grep -sEa "^og:" $tempdir/whois_temp | awk '{print $NF}' | tr -d ' ' | sort -u > $tempdir/net_orgs
grep -sEa "^nh:" $tempdir/whois_temp | awk '{print $NF}' | tr -d ' ' | sort -u > $tempdir/nh
grep -sEa "^oa:" $tempdir/whois_temp | awk '{print $NF}' | tr -d ' ' | sort -u > $tempdir/orgs
nets4=$(grep -sE "^in:" $tempdir/whois_temp | cut -d ':' -f 2- | tr -d ' ')
sed -e '/./{H;$!d;}' -e 'x;/in:/!d' $tempdir/whois_temp > $tempdir/nets4_raw
sed -e '/./{H;$!d;}' -e 'x;/i6:/!d' $tempdir/whois_temp > $tempdir/nets6_raw
[[ -f $tempdir/nets4_raw ]] && f_printWHOIS_TARGET "$tempdir/nets4_raw" > $tempdir/nets4
[[ -f $tempdir/nets6_raw ]] && f_printWHOIS_TARGET "$tempdir/nets6_raw" > $tempdir/nets6; fi
if [[ $poc_count -gt 0 ]]; then
cat $tempdir/whois_temp | sed -e '/./{H;$!d;}' -e 'x;/in:/d' | sed -e '/./{H;$!d;}' -e 'x;/i6:/d' |
sed -e '/./{H;$!d;}' -e 'x;/rt:/d' | sed -e '/./{H;$!d;}' -e 'x;/r6:/d' |
grep -sEa "^oa:|^on:|^an:|^aa:|^cy:|^ro:|^pn:|^it:|^mt:|^de:|^ad:|^ph:|^am:|^em:|^nh:|^ac:|^og:|^mb:" > $tempdir/pocs
f_HEADLINE2 "POINTS OF CONTACT (QUERY)\n"
echo ''; cat $tempdir/pocs | sed 's/^ac:/admin~/' | sed 's/^oa:/nnn\[ORG\]/g' | sed 's/^pn:/nnn\[PERSON\]/g' |
sed 's/^ro:/nnn\[ROLE\]/g' | sed 's/^it:/nnn\[IRT\]/g' | sed 's/mt:/nnn\[MNTNER\]/g' | sed 's/an:/nnn\[ASN\]/g' | sed 's/on:/-/' |
sed 's/an:/-/' | sed 's/de:/de~/' | sed 's/ph:/ph~/' | sed 's/ad:/ad~/' | sed 's/cy:/,/' | sed 's/mb:/|/' |
sed 's/nh:/|/' | sed 's/og:/org~/' | sed 's/am:/|/' | sed 's/em:/|/' | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' |
tr '[:space:]' ' ' | sed 's/nnn/\n\n\n\n/g' | sed 's/de~/\n\n/' | sed 's/de~//g' | sed 's/ad~/\n\n/' |
sed 's/org~/| Org:/g' | sed 's/ad~//g' | sed 's/admin~/\n\nAdmin:/' | sed 's/admin~//g' | sed 's/ph~/\n\n/' | sed 's/ph~//g' |
sed 's/^ *//' | sed 's/\]/\] /' | sed 's/ , /, /g' > $tempdir/poc_tmp
cat $tempdir/poc_tmp | sed '/./,$!d'; echo ''; fi
fi; fi
if [[ $netcount -gt 0 ]]; then
if [ -f $tempdir/net_orgs ] && [ -f $tempdir/orgs ]; then
orgs_other=$(comm -1 -3 $tempdir/net_orgs $tempdir/orgs | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d'); fi
if [ -f $tempdir/nh ] && [ -f $tempdir/adm ]; then 
admins_other=$(comm -1 -3 $tempdir/nh $tempdir/adm | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' | head -8); fi
if [ -n "$admins_other" ] || [ -n "$admins_other" ]; then
echo ''; f_HEADLINE2 "POINTS OF CONTACT (NETWORK)\n"
if [ -n "$orgs_other" ]; then
for o in $orgs_other; do
whois -h whois.$rir.net -- "--no-personal $o" > $tempdir/whois_org; echo ''; f_ORG_SHORT "$tempdir/whois_org"; echo -e "\n"; done; fi
if [ -n "$admins_other" ]; then
for a in $admins_other; do
echo ''; f_ADMIN_C "$a"; echo -e "\n"; done; fi; fi
if [[ $netcount4 -gt 0 ]]; then
echo '' > $tempdir/print_nets4; f_HEADLINE2 "NETWORKS (IPV4): $netcount4\n" >> $tempdir/print_nets4
if [[ $netcount4 -lt 41 ]] || [ $report = "false" ]; then
cat $tempdir/nets4 >> $tempdir/print_nets4
if [[ $netcount4 -lt 41 ]]; then
f_DEAGGREGATE "$nets4" >> $tempdir/print_nets4; fi; fi 
cat $tempdir/print_nets4
if [[ $netcount4 -gt 40 ]] && [ $report = "true" ]; then
echo -e "\nResults have been written to file: ${outdir}/RESOURCES_${rir}_${x}.txt\n"
cat $tempdir/print_nets4 >> ${outdir}/RESOURCES_${rir}_${x}.txt; cat $tempdir/nets4 >> ${outdir}/RESOURCES_${rir}_${x}.txt; fi; fi
if [[ $netcount6 -gt 0 ]]; then
echo '' > $tempdir/print_nets6; f_HEADLINE2 "NETWORKS (IPV6): $netcount6\n" >> $tempdir/print_nets6
[[ $netcount6 -lt 21 ]] || [[ $report = "false" ]] && cat $tempdir/nets6 >> $tempdir/print_nets6
cat $tempdir/print_nets6
if [[ $netcount6 -gt 20 ]] && [ $report = "true" ]; then
echo -e "\nResults have been written to file: ${outdir}/RESOURCES_${rir}_${x}.txt\n"
cat $tempdir/print_nets6 >> ${outdir}/RESOURCES_${rir}_${x}.txt
cat $tempdir/nets6 >> ${outdir}/RESOURCES_${rir}_${x}.txt; fi; fi; fi 
if [ -f $tempdir/orgs ]; then
for oid in $(cat $tempdir/orgs | sort -uV); do
echo '' ; f_netBLOCKS "${oid}"; done; fi
fi; done | tee -a ${out}
echo ''; unset rir; fi; unset target_type; unset x; f_Menu
;;
w3)
#************** ARIN OBJECT SEARCH *******************
f_makeNewDir; f_Long; unset filename; domain_enum="false"; target_type="other"
option_detail="2"; echo -e "${B}\nARIN OBJECT SEARCH > ${G}Expected input${D}\n"
echo -e "${bold}Net handles or other, e.g.  organizations (id/name), email addresses, abuse handles, etc.\n\nNot supported: IP-/network addresses${D}\n"
echo -e "\n${B}Options > ${G} OBJECT TYPE\n"; echo -e "${B} [1]${D} Net handles"
echo -e "${B} [2]${D} Other - points of contact only"
echo -e "${B} [3]${D} Other - all information"
echo -e -n "\n${B}  ? ${D}  " ; read object_type
echo ''; f_setTARGET
if [ $report = "true" ] ; then
echo -e -n "\n${B}Output  > ${G}OUTPUT - FILE NAME  ${B}>>${D}  " ; read filename
out="${outdir}/WHOIS.${filename}.txt"; fi
[[ $object_type = "1" ]] && target_type="nethandle" || target_type="whois_target"
for x in $(cat $tempdir/targets.list); do
echo ''; trimmed=$(echo $x | cut -d '/' -f 1 | cut -d '-' -f 1 | tr -d ' ')
if [[ $timmed =~ $REGEX_IP46 ]]; then
echo -e "\nRun options x), n) or ip) to query IP or network addresses\n"; else
rir="arin"; f_CLEANUP_FILES; if [ $target_type = "nethandle" ]; then
option_netdetails2="1"; f_WHOIS_NET "$x"; else
[[ -f $tempdir/org_tmp ]] && rm $tempdir/org_tmp; [[ -f $tempdir/org_nets ]] && rm $tempdir/org_nets; [[ -f $tempdir/poc ]] && rm $tempdir/poc;
unset org_match; unset poc_match; unset poc_query; unset org_count; unset poc_count; unset netcount_total; unset netcount2_total
x_caps=$(echo $x | tr [:lower:] [:upper:]); f_HEADLINE "$x_caps  [whois.arin.net]  $file_date"
if echo $x | grep -q '@'; then
mail_domain=$(cut -d '@' -f 2 <<<$x); org_query=$(cut -d '.' -f 1 <<<$mail_domain); poc_query="@$mail_domain"; net_query="$org_query"
elif echo $x | grep -q '\.'; then
org_query=$(cut -d '.' -f 1 <<<$x); poc_query="@$x"; net_query="$org_query"; else
org_query="$x"; net_query="$x"; poc_query="$x"; fi
org_match=$(whois -h whois.arin.net -- "o - $org_query" | sed '/^#/d' | grep ')')
org_count=$(echo "$org_match" | grep -c ')')
poc_match=$(whois -h whois.arin.net -- "p - $poc_query" | sed '/#/d' | grep ')')
poc_count=$(echo "$poc_match" | grep -c ')')
#ORGANIZATIONS
if [[ $org_count -gt 0 ]]; then
org_match_id=$(echo "$org_match" | cut -d '(' -f 2 | cut -d ')' -f 1 | tr -d ' ')
echo -e "\nORGANIZATION(S)\n"; echo "$org_match_id" > $tempdir/org_ids
if [[ $org_count -gt 1 ]]; then
echo "$org_match" | sed G; else
whois -h whois.arin.net -- "o + $org_match_id" > $tempdir/org_tmp; f_ORG "$tempdir/org_tmp"; fi; echo ''; fi
if [[ $poc_count -gt 0 ]]; then
poc_id=$(echo "$poc_match" | cut -d '(' -f 2 | cut -d ')' -f 1 | tr -d ' ')
if [[ $org_count -eq 1 ]]; then
poc_id=$(echo "$poc_match" | cut -d '(' -f 2 | cut -d ')' -f 1 | tr -d ' ' | grep -v "$org_match_id"); else
poc_id=$(echo "$poc_match" | cut -d '(' -f 2 | cut -d ')' -f 1 | tr -d ' '); fi; poc_id_count=$(wc -w <<<$poc_id)
#POCs
echo -e "\n$(echo $poc_query | tr [:lower:] [:upper:])  POINTS OF CONTACT"
if [[ $poc_count -lt 11 ]]; then
whois -h whois.arin.net -- "p + $poc_query" > $tempdir/poc
if [ -f $tempdir/poc ]; then
echo ''; sed -e '/./{H;$!d;}' -e 'x;/Name:/!d' $tempdir/poc |
grep -sEa "^Name:|^Handle:|^Company:|^City:|^StateProv:|^Country:|^Phone:|^Email:" | sed '/Name:/i nnn' | sed '/Name:/a ___-___' |
sed '/Handle:/a nnn___' | sed '/Country:/i ,' | sed '/Country:/a nnn___' | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' |
tr '[:space:]' ' ' | sed 's/nnn/\n\n/g' | sed 's/^ *//' | sed 's/___/ /g' | sed 's/ , /,/' | sed '/@/G'; echo ''; fi; else 
echo -e "$poc_match" |  sed 's/)/)\n\n /' | sed '/)/{x;p;p;x;}'; echo ''; fi; echo ''; fi
if [ $object_type = "3" ]; then 
#ASNs
asns=$(whois -h whois.arin.net -- "a - $org_query" | sed '/^#/d' | grep ')'); asn_count=$(echo "$asns" | grep -c ')')
[[ $asn_count -gt 0 ]] && echo -e "\n\nASNs\n" && echo "$asns\n" | sed '/)/{x;p;x}'
#NETWORKS
whois -h whois.arin.net -- "n > $net_query" > $tempdir/nets_tmp; netcount_total=$(grep -c '(NET' $tempdir/nets_tmp)
if [[ $netcount_total -gt 0 ]]; then
[[ $org_count -gt 0 ]] || [[ $poc_count -gt 0 ]] && f_Long
nets=$(sed -e '/./{H;$!d;}' -e 'x;/Subdelegations for/d' $tempdir/nets_tmp | grep -s '(NET'  | sed 's/)/)\n\n /' | sed '/)/{x;p;x}')
subdel=$(sed -n '/Subdelegations for/,$p' $tempdir/nets_tmp | grep -s '(NET' | sed 's/)/)\n /g' | sed '/ - /G' | sed '/(NET/G')
netcount=$(echo "$nets" | grep -c '(NET'); subcount=$(echo "$subdel" | grep -c '(NET')
if [[ $netcount -gt 0 ]]; then
echo -e "\n$(echo $net_query | tr [:lower:] [:upper:])  -  NETWORKS: $netcount\n"
if [[ $netcount -lt 71 ]]; then
echo -e "$nets\n"; else 
echo -e "\nOutput written to file: $outdir/${net_query}_RESOURCES.txt\n"
f_HEADLINE "$(echo $net_query | tr [:lower:] [:upper:])  NETWORKS | $netcount Networks | $file_date" >> ${outdir}/${net_query}}_RESOURCES.txt
echo -e "$nets\n" >> $outdir/${net_query}_RESOURCES.txt; fi; fi
if [[ $subcount -gt 0 ]]; then
echo -e "\n$(echo $net_query | tr [:lower:] [:upper:])  -  SUBDELEGATIONS: $subcount\n"
net_info=$(grep -sE "^NetRange:|^CIDR:|^NetName:|^NetHandle:|^OriginAS:|^Organization:" $tempdir/nets_tmp | sed '/NetRange:/{x;p;x}')
[[ -n "$net_info" ]] && echo -e "\n$net_info\n" && f_Long && echo ''
if [[ $subcount -lt 71 ]]; then
echo -e "$subdel\n"; else 
echo -e "Output written to file: $outdir/${net_query}_SUBDELEGATIONS.txt\n"
f_HEADLINE "$(echo $net_query | tr [:lower:] [:upper:]) SUBDELEGATIONS | $subcount Networks | $file_date" >> $outdir/${net_query}_SUBDELEGATIONS.txt
echo -e "$subdel\n" >> $outdir/${net_query}_SUBDELEGATIONS.txt; fi
net_org=$(f_ORG "$tempdir/nets_tmp"); [[ -n "$net_org" ]] && echo '' && f_Long && echo -e "\nORGANIZATION\n\n$net_org\n"; fi; fi
if [ -f $tempdir/org_ids ]; then
for oid in $(cat $tempdir/org_ids | sort -uV); do
echo '' ; f_netBLOCKS "${oid}"; done; fi; fi
fi; fi; done | tee -a ${out}; echo ''; unset rir; unset target_type; unset x; f_removeDir; f_Menu
;;
w4)
#************** pwhois.org BULK LOOKUPS *******************
f_makeNewDir ; f_Long; target_type="other"
echo -e "\n${B}pwhois.org Bulk Lookup (IPv4/IPv6)\n"
echo -e -n "\n${B}Target > ${D}PATH TO FILE ${B}>>${D}   " ; read input
echo -e -n "\n${B}Set   > ${D}OUTPUT - FILE NAME  ${B}>>${D}  " ; read filename
out="${outdir}/WHOIS/${filename}.txt"
grep -sEo "[0-9]{1,11}" $input | sort -ug > $tempdir/asns
if [[ $(grep -sEac "\.|:|/" $input) -gt 0 ]]; then
echo -e "\n${B}Option > Output Formatting (pwhois.org IP address lookups only)\n"
echo -e "${B} [1]${D}  Default" ; echo -e "${B} [2]${D}  Type Cymru (Table Layout)"
echo -e "${B} [3]${D}  BOTH" ; echo -e -n "\n${B}  ?${D}  " ; read option_pwhois
if [ $option_pwhois = "1" ] || [ $option_pwhois = "3" ] ; then
f_pwhoisBULK "${input}" | tee -a ${out}; fi
if [ $option_pwhois = "2" ] || [ $option_pwhois = "3" ] ; then
f_Long | tee -a ${out}; f_whoisTABLE  "${input}"; cat $tempdir/whois_table.txt | tee -a ${out}; fi; fi
if [ -f $tempdir/asns ]; then
f_HEADLINE "ASNs" | tee -a ${out}
for a in $(cat $tempdir/asns); do
dig +short as${a}.asn.cymru.com TXT | tr -d '"' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/|/G'; done | tee -a ${out}; fi
echo ''; unset target_type; unset x; f_removeDir; f_Menu
;;
w5)
#************** DOMAIN WHOIS LOOKUP *******************
f_makeNewDir ; f_Long; target_type="whois_target"; domain_enum="false"
out="${outdir}/WHOIS.DOMAINS.${file_date}.txt"; f_setTARGET; f_HEADLINE "DOMAIN WHOIS STATUS  |  $file_date" | tee -a ${out}
echo -e "Checking ...\n" | tee -a ${out}; cat $tempdir/targets.list | tee -a ${out}
for x in $(cat $tempdir/targets.list); do
f_WHOIS_STATUS "$x"; done | tee -a ${out}
if [ -f $tempdir/domains_ipv4 ] && [[ $(wc -l < $tempdir/targets.list) -gt 2 ]]; then
echo '' | tee -a ${out}; f_HEADLINE2 "IP ADDRESSES\n" | tee -a ${out}; f_printADDR "$(cat $tempdir/domains_ipv4)" | tee -a ${out}; fi
echo ''; unset target_type; unset x; f_removeDir; f_Menu
;;
q)
echo -e "\n${B}----------------------------------- Done -------------------------------------\n"
echo -e "                       ${BDim}Author - Thomas Wy, Mar 2023${D}\n\n" ; f_removeDir
unset outdir; unset output_folder; unset report; unset x; unset as; unset option_target; unset nssrv; unset rir
unset conn; unset option_connect; unset target_type; unset domain_enum; unset threat_enum; unset option_source
break
;;
esac
done

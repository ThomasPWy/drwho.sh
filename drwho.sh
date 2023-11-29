#!/usr/bin/env bash

#-------------------------------  API KEYS  -------------------------------

# *  hackertarget.com IP TOOLS  (expected:  api_key_ht='&apikey=APIkey')
#    api_key_ht="&apikey=""

# *  projecthoneypot.org
#   api_key_honeypot=""

#-------------------------------  BASIC VARIABLES  -------------------------------

output_folder="not saving results"; conn="${C}true${D}" # main menu status indicators
option_connect="1"; report="false"; quiet_dump="false"  # defaults
B="\033[1;34m"; D="\e[0m"; G="\033[1;32m"; R="\e[31m"; C="\e[38;5;51m"; bold="\e[1m"  # colors
temp="${PWD}/drwho_tmp"; outdir="${PWD}/drwho_tmp"  # temporary & permanent directories
ua_moz="Mozilla/5.0" # generic user agent, used with curl & whatweb
mac_prefixes="/usr/share/nmap/nmap-mac-prefixes"

#-------------------------------  REGEX  -------------------------------

REGEX_HOSTNAME="^[a-zA-Z0-9._-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,5}$"
REGEX_IP4="^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"
REGEX_NET4="^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{2,3}$"
REGEX_NETHDL4="\bNET-[0-9]{1,3}\-[0-9]{1,3}\-[0-9]{1,3}\-[0-9]{1,3}\-[0-9]{1,3}\b"
REGEX_NETHDL6="\bNET6\-[0-9]{1,4}\-[0-9A-F]{1,4}\-[0-9A-F]{1,4}([0-9A-F]{1,4}[0-9A-F]{1,4})?\b"
REGEX_MAC="((([0-9a-fA-F]{2})[ :-]){5}[0-9a-fA-F]{2})|(([0-9a-fA-F]){6}[:-]([0-9a-fA-F]){6})|([0-9a-fA-F]{12})"
REGEX_MAIL="\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b"
REGEX_PHONE="\+[0-9]{2,6}[ -][0-9]{2,4}[ -]([0-9]{2,8}|[0-9]{2,4}[ -][0-9]{2,8})"
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
'1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))'   #Thanks @https://stackoverflow.com/a/17871737
REGEX_NET6="${REGEX_IP6}+/{0,1}+[0-9]{0,2}"
HOSTNAME_ALT="\b[a-zA-Z0-9._-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,5}\b"
IP4_ALT="[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
IP4_NET_ALT="\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{2,3}\b"
IP4_HOST_NET="[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}+/{0,1}+[0-9]{0,2}"
IP4_RANGE="([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})+(\s?\-\s?)+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"
PATTERN_IWHOIS="\b(abuse-c|abuse-mailbox|admin-c|auth|author|fingerpr|form|irt-nfy|local-as|mbrs-by-ref|member-of|mnt-by|mnt-domains|mnt-irt|mnt-lower|mnt-nfy|mnt-ref|mnt-routes|notify|nserver|org|origin|person|ping-hdl|ref-nfy|tech-c|upd-to|zone-c)+;+[0-9a-z\-]{3,27}\b"

#**********************  DNS BLOCKLISTS  ***********************

blocklists_other="
all.s5h.net
b.barracudacentral.org
bl.spamcop.net
dnsbl.dronebl.org
dnsbl.tornevall.org
ix.dnsbl.manitu.net
phishing.rbl.msrbl.net
relays.bl.kundenserver.de
talosintelligence.com
virus.rbl.msrbl.net
"

#**********************  Monero Cryptomining Pools  ***********************

monero_pools="
pool.minexmr.com
fr.minexmr.com
de.minexmr.com
sg.minexmr.com
ca.minexmr.com
us-west.minexmr.com
pool.supportxmr.com
mine.c3pool.com
xmr-eu1.nanopool.org
xmr-eu2.nanopool.org
xmr-us-east1.nanopool.org
xmr-us-west1.nanopool.org
xmr-asia1.nanopool.org
xmr-jp1.nanopool.org
xmr-au1.nanopool.org
xmr.2miners.com
xmr.hashcity.org
xmr.f2pool.com
xmrpool.eu
pool.hashvault.pro
"

#**********************  SUBPAGES  (CONTACTS)  ***********************

subpages="
blog
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
imprint
de/kontakt
de/unternehmen
/de/ueber-uns/unternehmen
/de-de/ueber-uns/unternehmen
en/about
en/aboutus
en/contact
fr/contact
"
subpages2="
blog
careers
services
"

#------------------------------------- WEB SERVER  TARGET PORTS & NSE SCRIPTS  -------------------------------------
nse1="http-git,http-title,https-redirect,http-slowloris-check,irc-botnet-channels,ike-version,smb-double-pulsar-backdoor,smb-vuln-ms17-010,snmp-netstat,snmp-info,snmp-win32-shares,ssl-cert,ssl-heartbleed,ssl-known-key,sslv2,tftp-enum,vulners"
nse2="ftp-anon,http-methods,ms-sql-empty-password,mysql-empty-password,nfs-ls,rmi-vuln-classloader,smb-ls,ssh-auth-methods"
web0="ajp-headers,http-affiliate-id,http-apache-server-status,http-cookie-flags,http-date,http-malware-host,http-slowloris-check,http-traceroute,http-mobileversion-checker,http-php-version,http-referer-checker,ssl-date,ssl-known-key,xmlrpc-methods,http-trace"
web1="ajp-methods,ftp-anon,http-cors,http-methods,http-open-proxy,ssh-auth-methods,ssh2-enum-algos"
web2="http-auth,http-auth-finder,http-enum,http-jsonp-detection,http-phpmyadmin-dir-traversal,http-unsafe-output-escaping,http-webdav-scan,mysql-empty-password,rmi-vuln-classloader"
web3="http-csrf,http-dombased-xss,http-stored-xss"
ports_web="T:21,T:22,T:23,T:80,T:443,T:1080,T:1099,T:1433,T:1434,T:3306,T:8009,T:8080,T:8443"
top80="T:21,T:22,T:23,T:25,T:53,T:80,T:88,T:89,T:110,T:139,T:179,T:222,T:389,T:443,T:445,T:465,T:514,T:587,T:631,T:636,T:860,T:873,T:993,T:1025,T:1080,T:1194,T:1433,T:1434,T:1723,T:2000,T:2002,T:2049,T:2082,T:2083,T:2483,T:2484,T:3260,T:3306,T:3389,T:4444,T:5000,T:5060,T:5061,T:5222,T:5223,T:5432,T:5500,T:5800,T:5900,T:5938,T:6379,T:6443,T:6665,T:6666,T:8009,T:8040,T:8041,T:8080,T:8200,T:8443,T:8834,T:9001,T:9160,T:9200,T:9396,T:9800,T:10000,T:11211,T:27017,T:55000,U:123,U:161,U:162,U:500,U:514,U:5060"
top250="T:7,T:9,T:13,T:17,T:19-23,T:25,T:26,T:37,T:53,T:79,T:80,T:81,T:82,T:88,T:89,T:100,T:102,T:106,T:110,T:111,T:113,T:119,T:135,T:139,T:143,T:144,T:157,T:179,T:199,T:222,T:255,T:371,T:385,T:389,T:427,T:443,T:444,T:445,T:465,T:500,T:502,T:512-515,T:543,T:544,T:548,T:554-556,T:587,T:631,T:636,T:646,T:691,T:808,T:860,T:873,T:902,T:989,T:990,T:993,T:995,T:1000,T:1022,T:1024-1031,T:1038,T:1039,T:1041,T:1044,T:1048,T:1049,T:1053,T:1054,T:1056,T:1064,T:1065,T:1071,T:1080,T:1098,T:1099,T:1110,T:1194,T:1433,T:1434,T:1443,T:1515,T:1701,T:1720,T:1723,T:1755,T:1801,T:1883,T:1900,T:2000,T:2001,T:2049,T:2082,T:2083,T:2100,T:2103,T:2105,T:2107,T:2121,T:2222,T:2379,T:2380,T:2483,T:2484,T:2601,T:2717,T:2869,T:2967,T:3000,T:3001,T:3128,T:3260,T:3268,T:3269,T:3306,T:3333,T:3389,T:3478,T:3689,T:3690,T:3703,T:3986,T:4001,T:4333,T:4433,T:4444,T:4899,T:5000,T:5001,T:5004,T:5005,T:5009,T:5050,T:5051,T:5060,T:5101,T:5120,T:5190,T:5222,T:5223,T:5357,T:5432,T:5500,T:5631,T:5632,T:5666,T:5800,T:5900,T:5901,T:5938,T:5984,T:5985,T:6000-6009,T:6379,T:6443,T:6514,T:6646,T:6665,T:6666,T:6667,T:6679,T:6697,T:7000,T:7070,T:8000,T:8008,T:8009,T:8010,T:8031,T:8040,T:8041,T:8080,T:8081,T:8086,T:8088,T:8200,T:8443,T:8500,T:8834,T:8888,T:8901,T:8902,T:8903,T:9000,T:9001,T:9090,T:9100,T:9102,T:9160,T:9200,T:9391,T:9396,T:9501,T:9800,T:9999,T:10000,T:10010,T:10250,T:27017,T:31337,T:32768,T:49152,T:49153,T:49154,T:49155,T:49156,T:49157,T:50000-50003,T:50007,T:55000,U:67-69,U:161,U:162,U:500,U:514,U:3478,U:3479,U:3480,U:3481,U:5060,U:11211,U:31335,U:51820"
# ----------------------------------  DIRECTORIES  -------------------------------------

f_makeNewDir(){
[[ -d $temp ]] && rm -rf $temp; mkdir $temp
}

f_removeDir(){
[[ -d $temp ]] && rm -rf $temp
}

# ----------------------------------  GENERATE REPORTS FROM SCRIPT OUTPUT  -------------------------------------

f_REPORT(){
echo -e -n "\n${B}SET ${C}directory  >  ${D}HOME/${B}dir_name  >>${D}  " ; read dirname
if [ -n "$dirname" ]; then
[[ -d $HOME/$dirname ]] || mkdir $HOME/$dirname
outdir="$HOME/$dirname"; output_folder="$dirname"; report="true"
export outdir; export output_folder; export report; fi
}

# --------------.------  MANAGE PRIVILEGES & TARGET INTERACTION ------------------------

f_isADMIN(){ # -- checks if user is root or in sudoers group
is_root=$(whoami | grep -o 'root'); is_sudo=$(groups | grep -Eow "sudo|sudoers")
[[ -n "$is_root" ]] && echo "$is_root"; [[ -n "$is_sudo" ]] && echo "$is_sudo"
}

f_getDEFAULT_NS(){
if type resolvectl &> /dev/null; then
  default_ns=$(/usr/bin/resolvectl status | grep -m 1 'Current DNS Server:' | cut -d ':' -f 2- | awk '{print $1}' | grep -sEo "$REGEX_IP46")
  [[ -n "$default_ns" ]] && echo "$default_ns"
fi
}

f_targetCONNECT() {
echo -e "\n${B}Option  >${C}  Target Interaction  ${B}>${D}  Send packets from your IP to target systems?"
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
echo -e "\n${R}  Warning:${D} Selected option requires sending packets to target systems!"
echo -e "\n  Please deactivate non-connect mode via option c)" ; echo -e "\n  ${R}${IT}Aborting...${D}"
}

f_WARNING_PRIV(){
echo -e "\n${R}Sorry, this option requires elevated privileges${D}\n"
}

# -------------------------------------  CHECK DEPENDENCIES  -------------------------------------

f_ERROR_MESSAGE(){
echo -e "\nERROR: $1 is not installed on your system. Please make sure that at least the essential dependencies are satisfied."
echo -e "\nDependencies (essential):\n\ncurl, dnsutils (installs dig & host), jq, ipcalc, lynx, nc (netcat), nmap, nping, openssl, whois"
echo -e "\nDependencies (recommended):\n\ndublin-traceroute, mtr, thc-ipv6, tracepath, whatweb\n"
}

f_showHELP(){
echo -e "${B}"; f_Long; echo -e "\n ---------------\n  drwho.sh\n ---------------\n"
echo -e "https://github.com/ThomasPWy/drwho.sh,  Author: Thomas Wy,  Version: 6.1 (Nov 2023)"; f_Long ; echo -e "${D}"
echo -e "${C}DEPENDENCIES ${D}\n"
echo -e "\n${B}Dependencies (required):${D}\n"
echo "curl, dnsutils (installs dig, delv & host), jq, ipcalc, lynx, ncat, nmap, nping, openssl, whois"
echo -e "\n\n${B}Dependencies (recommended):${D}\n"
echo -e "dublin-traceroute, locate/mlocate, mtr, \ntestssl.sh, tracepath ('iputils-tracepath' in Debian/Ubuntu, 'tracepath' in Termux), thc-atk6, whatweb"
echo -e "${B}"; f_Long; echo -e "\n${C}CUSTOMIZATIONS${D}\n"
echo -e "\n${B}API KEYS ${D}\n"
echo -e "API keys are required for usage of Project Honeypot (projecthoneypot.org) and\nIP Quality Score (ipqualityscore.com) APIs"
echo -e "\nAn API key for hackertarget's IP API is recommended (required for the Nmap API)\nQueries are rate-limited without API key. (https://hackertarget.com)"
echo -e "\nnOptained API keys can be entered in the designated fields (script source, line 4)"
echo -e "\n\n${B}EXECUTABLES ${D}\n\nCustom paths to executables of dependencies can be set in the EXECUTABLES section, starting with line 302." 
echo -e "\n\n${B}NAME SERVERS ${D}\n"
echo -e "The name servers to be used for any DNS lookups and DNS-based APIs can be set via the dialogue shown when the script is started\n"
}

if ! type curl &> /dev/null; then
  f_ERROR_MESSAGE "curl"; f_showHELP; f_ERROR_MESSAGE "curl"; exit 1
fi
if ! type dig &> /dev/null; then
  f_ERROR_MESSAGE "dnsutils"; f_showHELP; f_ERROR_MESSAGE "dnsutils"; exit 1
fi
if ! type jq &> /dev/null; then
  f_ERROR_MESSAGE "jq"; f_showHELP; f_ERROR_MESSAGE "jq"; exit 1
fi
if ! type nc &> /dev/null; then
  f_ERROR_MESSAGE "nc"; f_showHELP; f_ERROR_MESSAGE "nc"; exit 1
fi
if ! type nmap &> /dev/null; then
  f_ERROR_MESSAGE "Nmap"; f_showHELP; f_ERROR_MESSAGE "Nmap"; exit 1
fi
if ! type ipcalc &> /dev/null; then
  f_ERROR_MESSAGE "ipcalc"; f_showHELP; f_ERROR_MESSAGE "ipcalc"; exit 1
fi
if ! type whois &> /dev/null; then
  f_ERROR_MESSAGE "whois"; f_showHELP; f_ERROR_MESSAGE "whois"; exit 1
fi

# ---------------------------------  MAIN MENU  -----------------------------------------

f_Menu(){
f_Long; echo -e "\n  ${B}Directory      >${D}${bold}  $output_folder${D}"
echo -e "\n  ${B}TargetConnect  >  ${G}$conn\n\n"
echo -e "${B}    x)   ${D}${bold}General Target Summaries/Details (All Sources)\n"
echo -e "${C}         ASNs|AS-Sets|Hostnames|IPs|Network Addresses & Names|OrgIDs|MAC Addr."
echo -e "\n${B}  Target-specific Information Gathering & Diagnostics:\n"
echo -e "${B}    b)   ${D}${bold}BGP${D} (Prefix Status, Looking Glass)"
echo -e "${B}    d)   ${D}${bold}Domain Recon${D}"
echo -e "${B}  dns)   ${D}${bold}DNS${D}"
echo -e "${B}    i)   ${D}${bold}IPv4 & Domain Threat- & Vulnerability Data"
echo -e "${B}    n)   ${D}${bold}Networks${D}"
echo -e "${B}    t)   ${D}${bold}Tools${D}"
echo -e "${B}  ssl)   ${D}${bold}SSL${D}"
echo -e "${B}   tr)   ${D}${bold}Tracerouting, Firewalk ${D}"
echo -e "${B}    w)   ${D}${bold}Whois${D}  (inverse, PoC & bulk lookups)"
echo -e "${B}  www)   ${D}${bold}Web Servers${D}"
echo -e "\n${B}    a)   Show ALL"
echo -e "${C}    c)   Toggle TARGET - CONNECT / NON-CONNECT Mode ${B}"
echo -e "   cc)   Clear the Screen"
echo -e "    h)   Help"
echo -e "${C}    s)   Save Results ${B}"
echo -e "    q)   Quit${D}"
}

# ----------------------------------  BANNER  ------------------------------------

 echo -e " ${B}
  ____                _           
 |  _ \ _ ____      _| |__   ___  
 | | | | '__\ \ /\ / / '_ \ / _ \ 
 | |_| | |   \ V  V /| | | | (_) |
 |____/|_|    \_/\_/ |_| |_|\___/ 
 ${D}"
echo -e "\033[3;39m  \"whois the Doctor? Who? Dr Who?\" ${D}"
option_connect="1"; is_admin=$(f_isADMIN); sys_ns=$(f_getDEFAULT_NS)
file_date=$(date -I)
#------------------------------  CHECK PRIVILEGES  -------------------------------

if [ -n "$is_admin" ]; then
    [[ "$is_admin" =~ "root" ]] || run_as_sudo="/usr/bin/sudo"
else
    run_as_sudo=""
fi
# ----------------------------------  CHOOSE DEFAULT NS  ------------------------------------

echo -e "\n\n\n${C}SET  ${B}>  ${C}NAME SERVER(s)${B} to use for any DNS lookup or DNS zone API query${D}\n"
echo -e "${B}  [1]${D}   Multiple public recursive resolvers:"
echo -e "${B}        1.0.0.1, 1.1.1.1, 8.8.4.4, 8.8.8.8, 9.9.9.9, 9.9.9.10, 134.195.4.2 (speeds up bulk queries)"
echo -e "${B}  [2]${D}   1.1.1.1"
echo -e "${B}  [3]${D}   8.8.8.8"
echo -e "${B}  [4]${D}   9.9.9.9"
echo -e "${B}  [4]${D}   134.195.4.2 (OpenNIC)"
echo -e "${B}  [5]${D}   System default: $sys_ns"
echo -e "${B}  [6]${D}   Set custom NS"
echo -e -n "\n${B}   ? ${D}   "; read option_ns
if [ $option_ns = "6" ]; then
    echo -e -n "\n${B}Set     >${C}  NAME SERVER  ${B} >>${D}   " ; read ns_input
    default_ns=$(echo "$ns_input" | tr -d ' ')
else
  [[ $option_ns = "1" ]] && default_ns="1.1.1.1" ; [[ $option_ns = "2" ]] && default_ns="1.1.1.1"
  [[ $option_ns = "3" ]] && default_ns="8.8.8.8"; [[ $option_ns = "4" ]] && default_ns="9.9.9.9"
  [[ $option_ns = "5" ]] && default_ns="$sys_ns"
fi
[[ -n "$default_ns" ]] || default_ns="1.1.1.1"
[[ $option_ns = "1" ]] && nmap_ns="--dns-servers=1.0.0.1,1.1.1.1,8.8.4.4,8.8.8.8,9.9.9.9,9.9.9.10,134.195.4.2" || nmap_ns="--dns-servers=${default_ns}"

#-------------------------------  EXECUTABLES  -------------------------------

CURL="/usr/bin/curl"
DATE="/usr/bin/date"
DIG="/usr/bin/dig @$default_ns -r"
DUBLINTR="/usr/bin/dublin-traceroute"
DUMP_DHCP6="/usr/bin/atk6-dump_dhcp6"
DUMP_ROUTER6="/usr/bin/atk6-dump_router6"
IP=$(command -v ip)
IPCALC="/usr/bin/ipcalc"
JQ="/usr/bin/jq -r"
LYNX="/usr/bin/lynx"
MTR="/usr/bin/mtr"
NMAP="/usr/bin/nmap"
NPING="/usr/bin/nping"
OPENSSL="/usr/bin/openssl"
PING="/usr/bin/ping"
TOUT="/usr/bin/timeout"
TPATH="/usr/bin/tracepath"
WHATWEB="/usr/bin/whatweb"
WHOIS="/usr/bin/whois"
WPSCAN=$(command -v wpscan)

if [ -f /usr/bin/nc ]; then
  NCAT="/usr/bin/nc"
elif  [ -f /usr/bin/ncat ]; then
  NCAT="/usr/bin/ncat"
else
  NCAT=$(command -v nc)
  [[ -n "$NCAT" ]] || NCAT=$(command -v netcat)
fi

# ----------------------- DOWNLOAD IX PREFIX LIST FROM PEERING DB  -----------------------

f_get_IX_PFX(){
if ! [ -f ${file_date}.ix_pfx.txt ]; then
  echo -e "\nDownloading IX Prefix List...\n"
  $CURL -m 30 -sL "https://www.peeringdb.com/api/ixpfx?protocol__in=IPv4" > $temp/ix_pfx4.json
  $JQ '.data[] | .prefix, .ixlan_id' $temp/ix_pfx4.json > ${file_date}.ix_pfx.txt
  $CURL -m 30 -sL "https://www.peeringdb.com/api/ixpfx?protocol__in=IPv6" > $temp/ix6.json
  $JQ '.data[] | .prefix, .ixlan_id' $temp/ix6.json >> ${file_date}.ix_pfx.txt
fi
}

# ----------------------------------  BOGON DETECTION  -------------------------------------

f_BOGON(){
bogon=""; bg_pfx=""; bg_type=""
local query=$(echo "$*" | tr -d ' ' | cut -d '/' -f 1 | cut -d '-' -f 1)
if [[ $query =~ $REGEX_IP46 ]]; then
  rev=$(f_REVERSE "$query")
  if [[ $query =~ $REGEX_IP4 ]]; then
    bg_pfx=$($DIG +short ${rev}.v4.fullbogons.cymru.com TXT | tr -d '\"' | sed 's/^ *//' | tr -d ' ')
  else
    bg_pfx=$($DIG +short ${rev}.v6.fullbogons.cymru.com TXT | tr -d '\"' | sed 's/^ *//' | tr -d ' ')
  fi
  if [ -n "$bg_pfx" ]; then
  bogon="TRUE"
    if [[ $query =~ $REGEX_IP4 ]]; then
      [[ $bg_pfx = "10.0.0.0/8" ]] && bg_type="RFC1918  (private internets)"
      [[ $bg_pfx = "172.16.0.0" ]] && bg_type="RFC1918  (private internets)"
      [[ $bg_pfx = "192.168.0.0/16" ]] && bg_type="RFC1918  (private internets)"
      [[ $bg_pfx = "100.64.0.0/10" ]] && bg_type="Carrier grade NAT"
      [[ $bg_pfx = "127.0.0.0/8" ]] && bg_type="Loopback"
      [[ $bg_pfx = "169.254.0.0/16" ]] && bg_type="Link local (APIPA)"
      [[ $bg_pfx = "192.0.2.0/24" ]] && bg_type="Reserved  (TEST-NET-1)"
      [[ $bg_pfx = "192.88.99.0/24" ]] && bg_type="Reserved  (former IPv6 to IPv4 relay)"
      [[ $bg_pfx = "198.18.0.0/15" ]] && bg_type="Reserved  (benchmarking)"
      [[ $bg_pfx = "198.51.100.0/24 " ]] && bg_type="Reserved (TEST-NET-2)"
      [[ $bg_pfx = "203.0.113.0/24" ]] && bg_type="Reserved  (TEST-NET-3)"
      [[ $bg_pfx = "224.0.0.0/4 " ]] && bg_type="IPv4 multicast"
      [[ $bg_pfx = "233.252.0.0/24" ]] && bg_type="Reserved (MCAST-TEST-NET)"
      [[ $bg_pfx = "240.0.0.0/4" ]] && bg_type="Reserved  (future use)"
    else
      bench=$(grep -sEoi "^2001:(2:0:|0002:|2::)" <<< $1 ); doc=$(grep -sEoi "^2001:(0)?db8:" <<< $1 )
      linkl=$(grep -sEoi "^fe[0-9a-f]{2}:" <<< $1 ); multi=$(grep -sEoi "^ff[0-9a-f]{2}" <<< $1 )
      orchid=$(grep -sEoi "^2001:(00)?[0-9a-f]{2}" <<< $1 ); ula=$(grep -sEoi "^f[c-d][0-9a-f]{2}:" <<< $1 )
      [[ -n "$bench" ]] && bg_type="Reserved  (benchmarking)"; [[ -n "$doc" ]] && bg_type="Reserved  (documentation)"
      [[ -n "$linkl" ]] && bg_type="Link local address"; [[ -n "$multi" ]] && bg_type="Multicast"
      [[ -n "$orchid2" ]] && bg_type="Reserved  (ORCHID2)"; [[ -n "$ula" ]] && bg_type="Unique local address (ULA)"
    fi
    else
    bogon="FALSE"; bg_type="NA"
  fi
else
bogon="NA"; bg_type="NA"
fi
export bogon; export bg_type; export bg_pfx
}

f_BOGON_INFO(){
f_BOGON "$1"
if [ $bogon = "TRUE" ]; then
  echo -e "$1  -   BOGON !  $bg_type\n"
  if [ $target_type != "net" ] && [ $target_type != "prefix" ]; then
    f_LOCAL_DNS "$1"
    if [[ $1 =~ $REGEX_IP6 ]]; then
      v6_info=$(f_IPV6_INFO "$1"); [[ -n "$v6_info" ]] && echo -e "\n$v6_info\n"
    fi
  fi
fi
}

# ----------------------------  COLLECT & FILTER TARGET INPUT   -------------------------------------

f_setTARGET(){
if [ $option_target = "1" ] || [ $option_target = "2" ]; then
  if [ $option_target = "2" ]; then
    echo -e -n "\n${B}Target  >  ${C}PATH TO FILE  ${D}e.g.  ./targets.txt  ${B}>>${D}  " ; read -r input
    cat $input > $temp/targets_raw
  else
    echo -e -n "\n${C}TARGET  ${B}>>${D}  " ; read -r input
    echo "$input" > $temp/targets_raw
  fi
  if [ -f $temp/targets_raw ]; then
    sed 's/^[ \t]*//;s/[ \t]*$//'  $temp/targets_raw | sed 's/  / /g' | sed 's/- /-/g' | sed 's/ -/-/g' | sed 's/,/\n/g' |
    sed 's/ /\n/g' | sed 's/^ *//' | sort -bifu > $temp/targets_tmp
    grep -sEwi -v "^pub$|^brt$|^arp$|^sys$|^dhcp$|^mtu$" $temp/targets_tmp > $temp/target_list
    f_FILTER_INPUT
  else
    echo -e "\nNo target provided"
  fi
else
  echo -e "\n\n${R}Error${D} - invalid choice\n"
fi
if [ -f $temp/target_list ] || [ -f $temp/targets_iwhois ]; then
  [[ -f $temp/targets_invalid ]] && echo -e "\n\n${R}INVALID TARGETS:\n" && cat $temp/targets_invalid && echo "${D}"
else
  echo -e "\n\n${R}NO VALID TARGETS PROVIDED\n${D}"
fi
}

f_FILTER_INPUT(){
grep -sEoi "$PATTERN_IWHOIS" $temp/targets_tmp > $temp/targets_iwhois
grep -sEwi -v "^pub$|^brt$|^arp$|^sys$|^dhcp$|^mtu$|${PATTERN_IWHOIS}" $temp/targets_tmp > $temp/target_list
if [ -f $temp/target_list ]; then
  for i in $(cat $temp/target_list); do
    trim=$(echo $i | cut -d '/' -f -1 | cut -d '-' -f -1);  check_ip=$(grep -sEo "$REGEX_IP46" <<< $trim)
    has_slash=$(echo $i | cut -s -d '/' -f -1);  has_dash=$(echo $i | cut -s -d '-' -f -1)
    # -------- FILTER & CATEGORIZE  IP ADDRESSES / NETWORKS  --------
    if [ -n "$check_ip" ]; then
      is_v4=$(grep -sEo "$REGEX_IP4" <<< $trim); [[ -n "$is_v4" ]] && ip_vers="4" || ip_vers="6"
      if [ -n "$has_slash" ] || [ -n "$has_dash" ]; then
        [[ -n "$is_v4" ]] && echo "$i" >> $temp/t_nets4 || echo "$i" >> $temp/t_nets6
      else
        [[ -n "$is_v4" ]] && echo "$i" >> $temp/t_hosts4 || echo "$i" >> $temp/t_hosts6
      fi
    else
      j=$(f_STRIP_URL "$i"); like_email=$(grep '@' <<< $j); is_email=$(grep -sEo "$REGEX_MAIL" <<< $j)
      is_hostname=$(grep -sEo "$HOSTNAME_ALT" <<< $j)
      if [ -n "$like_email" ]; then
        [[ -n "$is_email" ]] && echo "$j" | tee -a $temp/targets.list >> $temp/targets_email || echo "$j" >> $temp/invalid
      elif [ -n "$is_hostname" ]; then
        echo "$j" >> $temp/t_names
      else
        is_mac=$(grep -sEo "$REGEX_MAC" <<< $j); is_nethandle=$(grep -sEo "$REGEX_NETHDL4" <<< $j)
        is_as_set=$(grep -soi "as-" <<< $j)
        is_asn=$(echo "$j" | sed 's/[Aa][Ss][Nn]//' | sed 's/[Aa][Ss]//' | sed 's/[Aa]//' | tr -d '-' | tr -d ' ' |
        grep -v '[A-Za-z]' | grep -sEo "[0-9]{1,11}"); is_other=$(grep -sEav "\.|:|/|@|=|~" <<< $j)
        like_nh6=$(grep -sEo "$REGEX_NETHDL6" <<< $j)
        if [ -n "$is_as_set" ]; then
          echo "$j" >> $temp/t_as_set
        elif [ -n "$is_asn" ]; then
          echo "$j" | tr -d 'as' | tr -d 'AS' | tr -d ' ' >> $temp/t_asn
        elif [ -n "$is_nethandle" ]; then
          echo "$j" >> $temp/t_nh4_raw
        elif [ -n "$is_mac" ]; then
          echo "$j" >> $temp/t_mac
        elif [ -n "$is_other" ]; then
          if [ -n "$like_nh6" ]; then
            echo "$j" | tee -a $temp/t_undecided >> $temp/targets_nh6
          elif [ -n "$like_ga" ]; then
            echo "$j" | tee -a $temp/t_undecided >> $temp/targets_ga
          elif [ -n "$like_ix" ]; then
            echo "$j" | tee -a $temp/t_undecided >> $temp/targets_ix
          else
            echo "$j" >> $temp/t_other
          fi
        fi
      fi
    fi
  done
  [[ -f $temp/t_iwhois_raw ]] && sort -uV $temp/t_iwhois_raw > $temp/targets_iwhois
  [[ -f $temp/t_nets4 ]] && sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n $temp/t_nets4 | tee -a $temp/targets_nets > $temp/targets_net4
  [[ -f $temp/t_nets6 ]] && sort $temp/t_nets6 | tee -a $temp/targets_net > $temp/targets_net6
  [[ -f $temp/t_hosts4 ]] && sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n $temp/t_hosts4 | tee -a $temp/targets_ip  > $temp/targets_host4
  [[ -f $temp/t_hosts6 ]] && sort $temp/t_hosts6 | tee -a $temp/targets_ip > $temp/targets_host6
  [[ -f $temp/t_names ]] && sort -uV $temp/t_names | tee -a $temp/targets.list > $temp/targets_name
  [[ -f $temp/t_as_set ]] && sort -ug $temp/t_as_set | tee -a $temp/targets.list > $temp/targets_as_set
  [[ -f $temp/t_asn ]] && sort -ug $temp/t_asn | tee -a $temp/targets.list > $temp/targets_asn
  [[ -f $temp/t_nh4 ]] && sort -V $temp/t_nh4 | tee -a $temp/targets.list > $temp/targets_nh4
  [[ -f $temp/t_other ]] && sort -V $temp/t_other | tee -a $temp/targets.list > $temp/targets_other
  [[ -f $temp/t_undecided ]] && sort -V $temp/t_undecided | tee -a $temp/targets.list > $temp/targets_undecided
  [[ -f $temp/t_mac ]] && sort -V $temp/t_mac | tee -a $temp/targets.list > $temp/targets_mac
  [[ -f $temp/targets_nets ]] && cat $temp/targets_nets >> $temp/targets.list
  [[ -f $temp/targets_name ]] && cat $temp/targets_name > $temp/targets_trace
  [[ -f $temp/targets_ip ]] && cat $temp/targets_ip | tee -a $temp/targets_trace >> $temp/targets.list
fi
}

# ---------------------------------  EXTRACT DATA: IP/NET ADDRESSES  -----------------------------------------

f_EXTRACT_IP_ALL(){
[[ -f $1 ]] && extract_all=$(grep -sEo "$REGEX_IP4|$REGEX_IP6" $1) || extract_all=$(grep -sEo "$REGEX_IP4|$REGEX_IP6" <<< $1)
f_EXTRACT_IP4 "$extract_all"; f_EXTRACT_IP6 "$extract_all"
}

f_EXTRACT_IP4(){
extract_all=$(f_EXTRACT_IP4_ALL "$1")
if [ -n "$extract_all" ]; then
  echo "$extract_all" | grep -sEo "$REGEX_IP4"
  echo "$extract_all" | grep -s "/32" | awk -F'/32' '{print $1}' | grep -v '/'
fi
}

f_EXTRACT_IP4_ALL(){
[[ -f $1 ]] && extract4=$(grep -sEo "$IP4_HOST_NET" $1) || extract4=$(grep -sEo "$IP4_HOST_NET" <<< $1)
[[ -n "$extract4" ]] && echo "$extract4" | sort -u | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n
}

f_EXTRACT_NET4(){
[[ -f $1 ]] && net_input=$(grep -sEo "$REGEX_NET4" $1) || net_input=$(grep -sEo "$REGEX_NET4" <<< $1)
[[ -n "$net_input" ]] && echo "$net_input" | sort -u | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n
}


f_EXTRACT_IP6(){
extract_all=$(f_EXTRACT_IP6_ALL "$1")
if [ -n "$extract_all" ]; then
  echo "$extract_all" | grep -v '/' | grep -sEo "$REGEX_IP6" > $temp/extract6
  echo "$extract_all" | grep -s "/128" | awk -F'/128' '{print $1}' | grep -v '/' >> $temp/extract6
  [[ -f $temp/extract6 ]] && sort -bifu $temp/extract6
fi
}

f_EXTRACT_IP6_ALL(){
[[ -f $1 ]] && extract6=$(grep -sEo "$REGEX_IP6" $1) || extract6=$(grep -sEo "$REGEX_IP6" <<< $1)
[[ -n "$extract6" ]] && echo "$extract6" | sort -u
}

f_EXTRACT_NET6(){
extract_all=$(f_EXTRACT_IP6_ALL "$1")
[[ -n "$extract_all" ]] && echo "$extract_all" | grep '/' | grep -Ev "/128\b"
}


# ---------------------------------  EXTRACT DATA: OTHER  -----------------------------------------

f_EXTRACT_CERT(){
sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' <<< $1
}

f_EXTRACT_EMAIL(){
[[ -f $1 ]] && get_em=$(grep -sEaio "$REGEX_MAIL" $1) || get_em=$(grep -sEaio "$REGEX_MAIL" <<< $1)
[[ -n "$get_em" ]] && echo "$get_em" | tr [:upper:] [:lower:] | sort -u
}

f_EXTRACT_HOSTN(){
[[ -f $1 ]] && extract_h=$(grep -sEo "$HOSTNAME_ALT" $1) || extract_h=$(grep -sEo "$HOSTNAME_ALT" <<< $1)
[[ -n "$extract_h" ]] && echo "$extract_h" | tr [:upper:] [:lower:] | sort -u
}

# ---------------------------------  HANDLING TARGET CATEGORIES   -----------------------------------------

f_countL(){
/usr/bin/wc -l <<< "$1"
}

f_countW(){
/usr/bin/wc -w <<< "$1"
}

f_checkDOMAIN(){
check_soa=""; try_name=""
if [[ $(awk -F'.' '{print NF-1}' <<< $1) -eq 1 ]]; then
  [[ $($DIG soa +short $1 | head -1 | wc -w) -gt 3 ]] && echo "$1"
elif [[ $(awk -F'.' '{print NF-1}' <<< $1) -gt 1 ]]; then
  try_name=$(echo "$1" | rev | cut -d '.' -f -3 | rev)
  if [[ $($DIG soa +short $try_name | head -1 | wc -w) -gt 3 ]]; then
    echo "$try_name"
  else
    try_name=$(echo "$1" | rev | cut -d '.' -f -2 | rev)
     if [[ $($DIG soa +short $try_name | head -1 | wc -w) -gt 3 ]]; then
       echo "$try_name"
     fi
  fi
fi
}

# +++ IDENTIFY HOST/NET TYPES  +++
# -- Supplements f_FILTER_INPUT():
#  - identify newly discovered targets & additional properties of provided targets
#  - Nets/IPs: Public vs private/bogon IP, IPv4/v6, CIDR / net range; Hostnames: domain name 

f_getTYPE(){
local check_type="$*"
[[ -f $temp/host_domain ]] && rm $temp/host_domain
trimmed=$(echo "$check_type" | cut -d '/' -f -1 | cut -d '-' -f -1)
check_ip=$(grep -sEo "$REGEX_IP46" <<< $trimmed)
has_slash=$(echo "$check_type" | cut -s -d '/' -f -1); has_dash=$(echo "$check_type" | cut -s -d '-' -f -1)
if [ -n "$check_ip" ]; then
  f_BOGON "$trimmed"
  is_ipv4=$(grep -sEo "$REGEX_IP4" <<< $check_ip)
  [[ -n "$is_ipv4" ]] && ip_vers="4" || ip_vers="6"
  [[ -n "$has_slash" ]] && net_type="cidr"; [[ -n "$has_dash" ]] && net_type="range"; [[ -n "$net_type" ]] || net_type="null"
  if [[ $(echo "$bg_type" | grep -c 'RFC1918') -eq 1 ]]; then
    addr_type="private"
  else
    [[ $bogon = "TRUE" ]] && addr_type="bogon" || addr_type="public"
  fi
  if [ $ip_vers = "4" ]; then
    if [ -n "$has_slash" ] || [ -n "$has_dash" ]; then
      target_cat="net4"; host_type="null"
    else
      target_cat="host4"; host_type="ip"
    fi
  else
    if [ -n "$has_slash" ] || [ -n "$has_dash" ]; then
      target_cat="net6"; host_type="null"
    else
      target_cat="host6"; host_type="ip"
    fi
  fi
else
  net_type="null"; addr_type="null"; ip_vers="null"
  check_hostname=$(grep -sEo "$HOSTNAME_ALT" <<< $j)
  if [ -n "$check_hostname" ]; then
    target_cat="hostname"; host_type="hostname"
  else
    host_type="null"
    check_asn1=$(echo $1 | grep -sE "\b[0-9]{1,11}\b")
    check_asn2=$(echo $1 | sed 's/[Aa][Ss][Nn]//' | sed 's/[Aa][Ss]//' | sed 's/[Aa]//' | tr -d '-' | tr -d ' ' |
    grep -v '[A-Za-z]' | grep -sEo "[0-9]{1,11}")
    check_mail=$(grep -sEo "$REGEX_MAIL" <<< $j)
    check_other=$(grep -sEav "\.|:|/|@" <<< $1)
    if [ -n "$check_asn1" ] || [ -n "$check_asn2" ]; then
      target_cat="asn"
    elif [ -n "$check_other" ]; then
      target_cat="other"
    elif [ -n "$check_mail" ]; then
      target_cat="email"
    fi
  fi
fi
}

# *** Lists network IPs ***
f_LIST_IPS(){
$NMAP -sL -Pn -sn -n "$1" | grep 'Nmap scan report' | awk '{print $NF}' | sed '/1,1/d' | sed '$d'
}

f_getMAC_PFX(){
grep -i $(echo $1 | tr -d ':-' | cut -c -6) $mac_prefixes | cut -d ' ' -f 2- | sed 's/^ *//'
}

# *** Reverses IPv4 & IPv6 for APIs that use reverse DNS lookups ***
f_REVERSE(){
if [[ $1 =~ $REGEX_IP4 ]]; then
  reverse=$(awk -F'.' '{printf $4 "." $3 "." $2 "." $1}' <<<$1)
else
  reverse=$($DIG +noall +question -x $1 | awk -F'.ip6.' '{print $1}' | tr -d ';' | tr -d ' ')
fi
echo $reverse
}

f_STRIP_URL(){
echo "$1" | awk -F'://' '{print $NF}' | cut -d '/' -f 1
}

f_VALUE(){
local delim="$1"
local content="$2"
cut_input=$(cut -s -d "$delim" -f 2- <<< $content); f_TRIM "$cut_input"
}

# -------------------------------------  OUTPUT FORMATTING  -------------------------------------

f_HEADLINE(){
echo ''; f_Long; echo "[+]  $1"; f_Long; echo ''
}
f_HEADLINE2(){
echo ''; f_Long; echo -e "\n$1"
}
f_HEADLINE3(){
echo ''; f_Long; echo "$1"; f_Long
}
f_HEADLINE4(){
f_Long; echo -e "\n$1"
}

f_Long(){
echo -e "_______________________________________________________________________________\n"
}
f_Medium(){
echo -e "_______________________________________________________________\n"
}
f_Short(){
echo -e "____________________________________\n"
}
f_Long2(){
echo ''; f_Long; echo ''
}

f_printCSV(){
echo "$1" | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' | sed 's/^\,//' | sed 's/ ,/,/g' | sed 's/, /,/g' | sed 's/,/, /g' | sed 's/^ *//'
}

f_printTARGET_TYPE(){
searching=$(echo "$target_input" | tr  '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//' | fmt -s -w 100; echo '')
echo -e "\n\n--------------------------------------------\n"
echo -e "SEARCHING $1:\n\n$searching\n"
echo -e "--------------------------------------------\n"
}

f_toLOWER(){
tr [:upper:] [:lower:] <<< "$1"
}

f_toUPPER(){
tr [:lower:] [:upper:] <<< "$1"
}

f_printADDR(){
vers4=""; vers6=""
[[ -f $1 ]] && addr_input=$(grep -sE "$REGEX_IP46" $1) || addr_input=$(grep -sE "$REGEX_IP46" <<< $1)
if [ -n "$addr_input" ]; then
  vers4=$(f_EXTRACT_IP4_ALL "$addr_input"); vers6=$(f_EXTRACT_IP6 "$addr_input"); netwrk=$(cut -s -d '/' -f 1 <<<$addr_input)
  if [ -n "$netwrk" ]; then
    [[ -n "$vers4" ]] && echo "$vers4" | fmt -w 70 | sed G; [[ -n "$vers6" ]] && echo "$vers6" | fmt -w 70 | sed G
  else
    [[ -n "$vers4" ]] && echo "$vers4" | sed 's/ /  /g' | fmt -w 60;   [[ -n "$vers6" ]] && echo "$vers6" | sed 's/ /  /g' | fmt -w 60
  fi
fi
}

f_toOneLine(){
echo "$1" | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' | sed 's/nnn/\n\n/g' | sed 's/==/\n/g' | sed 's/~/:/g'
}

f_TRIM(){
echo "$1" | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d'
}

f_whoisFORMAT(){
local f="$*"
sed 's/% Information related to /Information related to /' ${f} | sed '/Source:/d' | sed '/fax:/d' | sed '/remarks:/d' |
sed 's/% Abuse contact/Abuse contact/' | sed '/^#/d' | sed '/%/d' | sed '/^$/d' | sed '/Abuse contact/{x;p;x;G;}' |
sed 's/Abuse contact for .*. is/\[@\] /' |
sed '/Information related/i \_______________________________________________________________________________\n' |
sed '/Information related/G' | sed 's/Information related to/* /'
}

# -------------------------------------  GET RIR & WHOIS DATA -------------------------------------

f_getRIR(){
export rir=$($CURL -s -m 20 --location --request GET "https://stat.ripe.net/data/rir/data.json?resource=$1" | $JQ '.data.rirs[0].rir' |
grep -sEo "RIPE|ARIN|AFRINIC|APNIC|LACNIC" | tr [:upper:] [:lower:])
}

f_get_RIPESTAT_WHOIS(){
[[ -f $temp/whois.json ]] && rm $temp/whois.json
$CURL -s -m 20 --location --request GET "https://stat.ripe.net/data/whois/data.json?resource=$1" > $temp/whois.json
if [ -f $temp/whois.json ]; then
  $JQ '.data.irr_records[]? | .[] | select (.key=="route"), select (.key=="origin") | .value' $temp/whois.json | sed '/\//i ==' |
  sed '/\//a - AS'| tr '[:space:]' ' ' | sed 's/== /\n/g' | sort -u | grep 'AS' > $temp/irr_records
fi
}

f_getWHOIS(){
if [ $rir = "lacnic" ] || [ $rir = "arin" ]; then
  $WHOIS -h whois.$rir.net $1 > $temp/whois
else
  if [ $option_detail = "1" ] || [ $option_detail = "3" ]; then
    $WHOIS -h whois.$rir.net -- "--no-personal $1" > $temp/whois_raw
  else
    $WHOIS -h whois.$rir.net -- "-B $1" > $temp/whois_raw
  fi
  sed -e '/./{H;$!d;}' -e 'x;/IANA1-RIPE/d' $temp/whois_raw  | sed -e '/./{H;$!d;}' -e 'x;/IANA-BLK/d' |
  sed 's/-GRS//' | sed 's/# Filtered//' | grep -saEv "DUMY-RIPE|RIPE-NCC-HM-MNT|RIPE-NCC-LEGACY-MNT|RIPE-NCC-END-MNT" > $temp/whois
fi
}

# -------------------------------------  GET NETWORKS, NET NAME & NET RANGES  -------------------------------------

f_getNETS(){
local f="$*"
sed '/source:/G' $f | sed -e '/./{H;$!d;}' -e 'x;/netname:/!d' |
grep -sEa "^inet(6)?num:|^netname:|^country:|^org:|(^abuse|^admin)-c:|^mnt-by:|^mnt-irt:|^source:" |
sed '/source:/G' | sed '/inetnum:/{x;p;x;}' | sed '/inet6num:/{x;p;x;}' > $temp/nets_raw
}

f_getNETS4(){
local f="$*"; f_getNETS "$f" | sed '/inetnum:/{x;p;x;}' | sed '/source:/G' | sed -e '/./{H;$!d;}' -e 'x;/inetnum:/!d'
}

f_getNETS6(){
local f="$*"; f_getNETS "$f" | sed '/inet6num:/{x;p;x;}' | sed '/source:/G' | sed -e '/./{H;$!d;}' -e 'x;/inet6num:/!d'
}

f_getNETNAME(){
if [ $rir != "lacnic" ]; then
  if [ $target_type = "net" ]; then
    ntn=$(f_VALUE ":" "$(grep -sai -m 1 '^netname:' $temp/whois)")
  else
    if [ $rir = "arin" ]; then
      ntn=$($JQ '.data.records[]? | .[] | select (.key=="NetName") | .value' $temp/whois.json | tail -1)
    else
      ntn=$($JQ '.data.records[0]? | .[] | select (.key=="netname") | .value' $temp/whois.json)
    fi
  fi
fi
[[ -n "$ntn" ]] && echo "$ntn"
}

f_getNET_RANGE(){
range=""; cidr=""; stripped=$(echo "$1" | cut -d '/' -f 1 | cut -d '-' -f 1)
if [ $rir = "arin" ]; then
   cidr=$($JQ '.data.records[]? | .[] | select (.key=="CIDR") | .value' $temp/whois.json | tail -1)
   cidr_count=$(f_countW "$cidr")
   if [[ $cidr_count -gt 0 ]] && [[ $cidr_count -lt 4 ]]; then
     netaddr="$cidr"
   else
     netaddr=$($JQ '.data.records[]? | .[] | select (.key=="NetRange") | .value' $temp/whois.json | tail -1)
   fi
else
  netaddr=$($JQ '.data.records[]? | .[] | select (.key=="inetnum") | .value' $temp/whois.json | tail -1 | sed s'/-/ - /')
  [[ -z "$netaddr" ]] && netaddr=$($JQ '.data.records[]? | .[] | select (.key=="inet6num") | .value' $temp/whois.json | tail -1)
fi
[[ -n "$netaddr" ]] && echo "$netaddr"
}

# -------------------------------------  ORGANIZATIONS  -------------------------------------

f_getORG(){
if [ $rir = "lacnic" ]; then
  if [ -f $temp/whois ]; then
    owner=$(f_VALUE ":" "$(grep -sai -m 1 '^owner:' $temp/whois)")
    owner_c=$(f_VALUE ":" "$(grep -sai -m 1 '^owner-c:' $temp/whois)")
    owner_cc=$(f_VALUE ":" "$(grep -sai -m 1 '^country:' $temp/whois)")
    owner_mail=$(grep -A 5 "$owner_c" $temp/whois | grep -sEo "$REGEX_MAIL" | sort -u | tr '[:space:]' ' '; echo '')
    echo "$owner, $owner_cc  $owner_mail"
  else
    $JQ '.data.records[]? | .[] | select (.key=="owner") | .value' $temp/whois.json
  fi
else
  if [ -n "$net_org" ]; then
    if [ $rir = "arin" ]; then
      echo "$net_org"
    else
      $WHOIS -h whois.$rir.net -- "--no-personal $net_org" > $temp/org && f_ORG_SHORT "$temp/org"
    fi
  fi
fi
}

f_getORGS(){
local f="$*"; sed -n '/organisation:/,/organisation:/p' ${f}  | sed '$d' | sed -e '/./{H;$!d;}' -e 'x;/org-name:/!d'
}

f_getORG_NAME(){
og=""
if [ $rir = "arin" ] || [ $rir = "lacnic" ]; then
  if [ $option_detail = "0" ] || [ $target_type != "net" ]; then
    [[ $rir = "arin" ]] && og=$($JQ '.data.records[]? | .[] | select (.key=="Organization") | .value' $temp/whois.json | tail -1)
    [[ $rir = "lacnic" ]] && og=$($JQ '.data.records[]? | .[] | select (.key=="owner") | .value' $temp/whois.json)
  fi
fi
[[ -n "$og" ]] || og=$(f_getPWHOIS_ORG)
if [ -z "$og" ]; then
  [[ $target_type = "net" ]] || og=$($JQ '.org' $temp/geo.json)
  [[ -z "$og" ]] && [[ -f $temp/pwhois ]] && og=$(f_VALUE ":" "$(grep -sE '^AS-Org-Name:' $temp/pwhois)")
fi
[[ -n "$og" ]] && echo "$og"
}

f_ORG_SHORT(){
local f="$*"
orgn=$(grep -Ea -m 1 "^org-name:" $f | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
orgid=$(grep -Ea -m 1 "^organisation:" $f  | awk '{print $NF}' | sed 's/^[ \t]*//;s/[ \t]*$//')
if [ -n "$orgn" ]; then
  sed -e '/./{H;$!d;}' -e 'x;/route:/d' $f  | sed -e '/./{H;$!d;}' -e 'x;/org-name:/!d' > $temp/org_temp
  if [ -f $temp/org_temp ]; then
    org_geo=$(grep -sEa -m 1 "^country:" $temp/org_temp | awk '{print $NF}' | sed 's/^[ \t]*//;s/[ \t]*$//')
    org_mail=$(f_EXTRACT_EMAIL "$temp/org_temp")
    org_ph=$(grep -sEa -m 1 "^phone:" $temp/org_temp | cut -d ':' -f 2- | sed 's/^ *//')
    [[ -z "$org_geo" ]] && org_geo=$(grep -sEa "^address:" $temp/org_temp | tail -1 | awk '{print $NF}' | sed 's/^[ \t]*//;s/[ \t]*$//')
    if [ $domain_enum = "false" ] && [ $target_type = "other" ] || [ $target_type = "whois_target" ]; then
      org_address=$(grep -sEa "^address:" $temp/org_temp | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' '; echo '')
      if [ $target_type = "whois_target" ]; then
        echo -e "[ORG]  $orgn  ($orgid), $org_ph $org_mail\n\n $org_address\n"
      else
        echo -e "$orgn  ($orgid), $org_ph $org_mail\n\n $org_address\n"
      fi
    else
      [[ $option_detail = "2" ]] && echo "$orgn ($orgid), $org_geo" || echo "$orgn ($orgid), $org_geo  $org_ph $org_mail"
    fi
  fi
fi
}

# -------------------------------------  POINTS OF CONTACT  -------------------------------------

f_ABUSEC_FINDER(){
$CURL -s -m 20 --location --request GET "https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=$1" > $temp/ac.json
rir_name=$(jq -r '.data.authoritative_rir' $temp/ac.json)
abuse_contacts=$(jq -r '.data.abuse_contacts[]' $temp/ac.json | tr '[:space:]' ' '; echo '')
if [ -z "$abuse_contacts" ] && [ -n "$rir_name" ]; then
  if [ $rir_name = "lacnic" ]; then
    $TOUT 20 $WHOIS -h whois.lacnic.net $1 > $temp/whois; abuse_contacts=$(f_printLACNIC_ABUSE_C "$temp/whois")
  else
    if [ $rir_name = "arin" ]; then
      $TOUT 20 $WHOIS -h whois.arin.net z $1 > $temp/whois
    else
      echo -e "\n$1: No abuse contact found. Searching any other email contacts instead\n"
      $TOUT 20 $WHOIS -h whois.$rir_name.net > $temp/whois
    fi
    abuse_contacts=$(grep -sEa -m 1 "^AbuseEmail:|^OrgAbuseEmail:|^% Abuse|^abuse-mailbox:|e-mail:|$REGEX_MAIL" $temp/whois |
    grep -sEao "$REGEX_MAIL" | sort -u | tr '[:space:]' ' '; echo '')
  fi
fi
if [ -n "$abuse_contacts" ]; then
  echo -e "\n $1 ($rir_name)  =>  $abuse_contacts\n"
else
  echo -e "\n $1 ($rir_name)   -  No abuse contacts found\n"
fi
}

f_ADMIN_C(){
if ! [ $rir = "arin" ] && ! [ $rir = "lacnic" ]; then
  $TOUT 20 $WHOIS -h whois.$rir.net -- "-F $1" | tr -d '*' | sed 's/^ *//' > $temp/adm
  if [ -f $temp/adm ]; then
    grep -E "^pn:|^ro:|^ad:|^\+|^ph:|^em:|^am:|^nh:" $temp/adm | sed '/+000000000/d' | sed 's/^ad:/ad~/' | sed 's/pn:/pn~/' | sed 's/:/:|/' |
    cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' | sed 's/pn~ /\n\n/g' | sed 's/ro~ /\n\n/g' | sed 's/ad~/\n\n/' |
    sed 's/ad~/\n\n/' | sed 's/ad~ //g' | sed 's/|/\n\n/' | sed '/|/G' | sed '/./,$!d'
  fi
fi
}

f_getRIR_OBJECTS(){
local f="$*"; rir_objects=$(grep -E "^oa:|^og:|^ac:|^tc:|^mb:|^it:|^abuse-c:|^abuse-mailbox|^admin-c:|^irt:|^mnt-by:|^mnt-lower:|^org:|^origin:|^tech-c:|upd-to:)" ${f} | sed '/RIPE-NCC-*/d' | sed 's/ac:/admin-c:/' | sed 's/oa:/org:/' | sed 's/og:/org:/' | sed 's/tc:/tech-c:/' | sed 's/mb:/mnt-by:/' |
sed 's/it:/irt-/' | sed 's/irt:/irt-/' | sed '/^$/d' | tr ':' ';' | tr -d ' ' | sort -uV | tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//')
if [ -n "$rir_objects" ]; then
  printRIR_OBJ=$(echo "$rir_objects" | sed 's/ /  /g' | sed G)
  if [ $domain_enum = "true" ]; then
    n_name=$(grep -sE -m1 "^netname:" ${f} | awk '{print $NF}' | tr -d ' ')
    net_addr_range=$(grep -sEa -m 1 "^inet(6)?num" $f | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
    net_country=$(grep -sEa -m 1 "^inet(6)?num" $f | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
    net_deag=$($IPCALC -r "$(echo "$net_addr_range" | tr -d ' ')" | grep '/' | tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//'; echo '')    
    f_HEADLINE2 "$n_name POCs ($(f_toUPPER "$rir"))\n"
    echo -e "$net_addr_range ($netcountry) - $net_deag\n"
  else
    if [ $target_type = "other" ] || [ $target_type = "inverse_whois" ]; then
      echo -e "\nPOCs:\n"
    elif [ $target_type = "whois_target" ]; then
      f_HEADLINE2 "$x POC OBJECTS ($(f_toUPPER "$rir"))\n\n"
    else
      f_HEADLINE2 "$(f_toUPPER "$rir") POCs (Searchable in option [w1])\n\n"
    fi
  fi
  echo -e "$printRIR_OBJ" | fmt -s -w 80; echo ''
fi
}

f_grepRIR_OBJECTS(){
local f="$*"; grep -sEv ":|/" $f |
grep -sEoi "\b(abuse-c|abuse-mailbox|admin-c|auth|author|fingerpr|form|irt-nfy|local-as|mbrs-by-ref|member-of|mnt-by|mnt-domains|mnt-irt|mnt-lower|mnt-nfy|mnt-ref|mnt-routes|notify|nserver|org|origin|person|ping-hdl|ref-nfy|tech-c|upd-to|zone-c)+;+[0-9a-z\-]{3,27}\b" | sort -uV
}

f_DOMAIN_POC(){
local adlist="$*"
[[ -f $temp/role ]] && rm $temp/role; [[ -f $temp/mnt_irt ]] && rm $temp/mnt_irt
[[ -f $temp/person ]] && rm $temp/person
if [[ $(grep -c 'role:' $adlist) -gt 0 ]]; then
  sed -e '/./{H;$!d;}' -e 'x;/role:/!d' $adlist > $temp/role
  f_POC "$temp/role"
elif [[ $(grep -c 'person:' $adlist) -gt 0 ]]; then
  sed -e '/./{H;$!d;}' -e 'x;/person:/!d' $adlist >> $temp/person
  f_POC "$temp/person"
elif [[ $(grep -c 'mnt-irt:' $adlist) -gt 0 ]]; then
  sed -e '/./{H;$!d;}' -e 'x;/mnt-irt:/!d' $adlist > $temp/mnt_irt
  f_POC "$temp/mnt_irt"
fi
}

f_POC(){
local whois_file="$*"
if [ $rir = "arin" ] || [[ $whois_file = $temp/arin_org ]]; then
  [[ $target_type = "net" ]] && echo '' && f_Long
  echo ''
  grep -sE "^OrgName:|^OrgId:|^Address:|^City:|^StateProv:|^PostalCode:|^Country:" $whois_file | sed '/OrgId:/a )nnn' | sed '/OrgId:/i (' |
  sed '/^City:/i,' | sed '/^City:/a __' | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' | sed 's/nnn/\n\n/g' |
  sed 's/__//' | sed 's/ ,/,/' | sed 's/( / (/' | sed 's/ )/)/'; echo ''
  if [ $option_detail = "2" ]; then
    grep -E "^(Org)?+Abuse+(Name:|Phone:|Email:)" $whois_file | sed '/AbuseName:/i nnn' | sed '/AbuseName:/a ===' | cut -d ':' -f 2- |
    sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' | sed 's/nnn/\n\n/g' | sed 's/===/\n\n  /g'; echo ''
    grep -E "^(Org)?+Tech+(Name:|Phone:|Email:)" $whois_file | sed '/TechName:/i nnn' | sed '/TechName:/a ===' | cut -d ':' -f 2- |
    sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' | sed 's/nnn/\n\n/g' | sed 's/===/\n\n  /g'; echo ''
  else
    grep -sE -m 2 "^(Org)?Abuse(Email:|Phone:)" $whois_file > $temp/poc_tmp
    grep -sE -m 2 "^(Org)?Tech(Email:|Phone:)" $whois_file >> $temp/poc_tmp
    if [ -f $temp/poc_tmp ]; then
      sed '/AbusePhone:/i nnnAbuse~' $temp/poc_tmp | sed '/TechPhone:/i nnnTech~' | sed '/Phone:/a __' | cut -d ':' -f 2- |
      sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' | sed 's/nnn/\n\n  /g' | sed 's/__//' | sed 's/~/: /' | sed 's/Tech:/Tech: /'; echo ''
      rm $temp/poc_tmp
    fi
  fi
elif [ $rir = "ripe" ] || [ $rir = "apnic" ] || [ $rir = "afrinic" ]; then
  [[ -f $temp/print_poc ]] && rm $temp/print_poc; [[ -f $temp/poc_input ]] && rm $temp/poc_input
  grep -sEav "RIPE-NCC-HM-MNT|RIPE-NCC-LEGACY-MNT" $whois_file | sed -e '/./{H;$!d;}' -e 'x;/netname:/d' |
  sed -e '/./{H;$!d;}' -e 'x;/route:/d' | sed -e '/./{H;$!d;}' -e 'x;/aut-num:/d' | sed -e '/./{H;$!d;}' -e 'x;/as-block:/d' |
  grep -sEa "^organisation:|^org-name:|^person:|^role:|^irt:|^address:|^e-mail:|^phone:" > $temp/poc_input
  while read line; do
    org_hdl=$(echo $line | grep -sa '^organisation:')
    org_name=$(echo $line | grep -sa '^org-name:')
    role=$(echo $line | grep -sa "^role:")
    person=$(echo $line | grep -sa "^person:")
    admin_hdl=$(echo $line | grep -sa '^nic-hdl:')
    poc_addr=$(echo $line | grep -sa '^address:')
    mnt_by=$(echo $line | grep -sa '^mnt-by:' | grep -v 'RIPE-NCC-HM-MNT')
    details=$(echo $line | grep -sEa "^phone:|^e(-)?mail:")
    [[ -n "$org_hdl" ]] && echo -e "ORG_HDL\n$org_hdl"
    [[ -n "$org_name" ]] && echo -e "ONAME\n$org_name"
    [[ -n "$role" ]] && echo -e "ROLE\n$role"
    [[ -n "$person" ]] && echo -e "PERSON\n$person"
    [[ -n "$admin_hdl" ]] && echo -e "NIC_HDL\n$admin_hdl"
    [[ -n "$poc_addr" ]] && echo -e "ADDRESS\n$poc_addr"
    [[ -n "$details" ]] && echo -e "DETAILS\n$details"
    [[ -n "$mnt_by" ]] && echo -e "MNT_BY\n$mnt_by"
  done < $temp/poc_input > $temp/print_poc; echo ''
  cut -d ':' -f 2- $temp/print_poc | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' |
  sed 's/ORG_HDL /\n\n\nORG:  /g' | sed 's/ROLE /\n\n\nROLE: /g' | sed 's/PERSON/\n\n\n/g' |
  sed  's/^ *//' | sed 's/ONAME/ /' | sed 's/ADDRESS/\n\n/' | sed 's/ADDRESS/\n\n/' |
  sed 's/ADDRESS//g' | sed 's/DETAILS/\n\n/' | sed 's/DETAILS//g' | sed 's/NIC_HDL/|/g' |
  sed 's/MNT_BY/|/g' | sed '/./,$!d'
fi; echo ''
}

f_printPOC_ADDITIONS(){
local whois_file="$*"
notify=$(f_EXTRACT_EMAIL "$(grep -sa -m 1 '^notify:' $whois_file)")
abu_mbox=$(f_EXTRACT_EMAIL "$(grep -sa -m 1 '^abuse-mailbox:' $whois_file)")
if [ -n "$notify" ] || [ -n "$abuse_mbox" ]; then
  [[ -n "$abu_mbox" ]] && print_abu_mbox="ABUSE: $abuse_mbox"; [[ -n "$notify" ]] && print_notify="NOTIFY: $notify"
  echo -e "$print_abu_mbox  $print_notify" | sed 's/^[ \t]*//;s/[ \t]*$//'
fi
}

# -------------------------------------  WHOIS: RIR/LIR SPECIFIC -------------------------------------

f_ARIN_CUST(){
cust_id=$(echo "$1" | grep -sEo "C+[0-9]{8,10}")
if [ -n "$cust_id" ]; then
  $TOUT 10 $WHOIS -h whois.arin.net "e $1" > $temp/org_summary
  cust_name=$(f_VALUE ":" "$(grep -s -m 1 'CustName:' $temp/org_summary)")
  cust_city=$(f_VALUE ":" "$(grep -s -m 1 'City:' $temp/org_summary)")
  cust_country=$(f_VALUE ":" "$(grep -s -m 1 'Country:' $temp/org_summary)")
  echo -e "\nCustomer $1:  $cust_name  $cust_city, $cust_country\n"; rm $temp/org_summary
fi
}

f_JPNIC_WHOIS(){
$WHOIS -h whois.nic.ad.jp "${1}/e" > $temp/jpnic
if [ -f $temp/jpnic ]; then
  jpn_name=$(grep -E "^c\." $temp/jpnic | grep 'Last' | cut -s -d ']' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
  jpn_hdl=$(grep -E "^a\." $temp/jpnic | grep 'Handle' | awk '{print $NF}')
  jpn_org=$(grep -E "^g\." $temp/jpnic | grep 'Organization' | cut -s -d ']' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
  grep -E "\[TEL\]" $temp/jpnic | cut -s -d ']' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' > $temp/jpnic_poc
  f_EXTRACT_EMAIL "$temp/jpnic" >> $temp/jpnic_poc
  [[ -f $temp/jpnic_poc ]] && jpnic_poc=$(cat $temp/jpnic_poc | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' | sed 's/^ *//'; echo '')
  if [ -n "$jpn_name" ] || [ -n "$jpn_org" ]; then
    [[ $target_type != "hop" ]] && f_HEADLINE2 "CONTACT\n" || echo -e "\n\nCONTACT\n"
    echo -e "\n$jpn_name ($jpn_hdl)  $jpn_org"
    [[ -n "$temp/jpnic_poc" ]] && echo -e "\n$jpnic_poc\n"
  fi
fi
}

f_LACNIC_POC(){
owner=$(f_getORG); responsible=$(f_VALUE ":" "$(grep -sai -m 1 '^responsible:' $temp/whois)")
owner_c=$(f_VALUE ":" "$(grep -sai -m 1 '^owner-c:' $temp/whois)")
owner_mail=$(grep -A 5 "$owner_c" $temp/whois | grep -sEo "$REGEX_MAIL" | sort -u | tr '[:space:]' ' '; echo '')
tech_c=$(f_VALUE ":" "$(grep -sai -m 1 '^tech-c:' $temp/whois)")
tech_mail=$(grep -A 5 "$tech_c" $temp/whois | grep -sEo "$REGEX_MAIL" | sort -u | tr '[:space:]' ' '; echo '')
if [ $domain_enum = "true" ]; then
  f_Long; echo -e "\n$owner"
  echo -e "\nOwner Contact: $owner_mail"; echo -e "\nAbuse Contact: $(f_printLACNIC_ABUSE_C)"
else
  echo -e "\nOwner:        $owner"
  echo -e "\nResponsible:   $responsible; tech contact: $tech_mail"  
fi
}

f_LACNIC_WHOIS(){
local s="$*"
if [ $option_detail = "0" ]; then
  f_get_RIPESTAT_WHOIS "$s"; f_NET_HEADER "$s"
else
  owner=$(f_getORG); net_addr=$(grep -sEa "^inetnum:|^inet6num:" $temp/whois | awk '{print $NF}' | tr -d ' ')
  net_geo=$(f_NETGEO "$net_addr"); netabuse=$(f_printLACNIC_ABUSE_C)
  created=$(f_VALUE ":" "$(grep -m 1 '^created:' $temp/whois)" | tr -d ' ' | cut -c -4)
  if [ $target_type != "net" ]; then
    echo -e "\nNet:          $net_addr (LACNIC)"
  else 
    f_HEADLINE3 "[NET]   $s  (query)  -  $file_date"
    [[ -n "$netabuse" ]] && echo -e "[@]: $netabuse\n___\n"
    echo -e "\nNet:          $net_addr (LACNIC)"
    range=$($IPCALC -b -n "$s"  | grep -E "^Address:|Broadcast:" | sed 's/Broadcast:/-/' | cut -d ':' -f 2- |
    sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' '; echo '')
    echo -e "\nRange:        $range"
    echo -e "\nStatus:       Created: $created | Country: $net_geo\n"
  fi
  f_LACNIC_POC; echo ''; f_ROUTE; [[ $target_type = "net" ]] && f_printAUTH_NS
fi
}

f_printLACNIC_ABUSE_C(){
local s="$*"
abusec=$(grep -sEai -m 1 "^abuse-c:" $f | awk '{print $NF}' | tr -d ' ')
print_abusec=$(sed -e '/./{H;$!d;}' -e 'x;/person:/!d' $f | grep -sEa "^nic-hdl.*|^e-mail:" | grep -a -A 1 "$abusec" |
grep -sEao "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" | sort -u | tr '[:space:]' ' '; echo '')
[[ -n "$print_abusec" ]] && echo "$print_abusec"
}

# -------------------------------------  PHWHOIS.ORG  -------------------------------------

f_getPWHOIS_ORG(){
if [ -f $temp/pwhois ]; then
  pnet=$(f_VALUE ":" "$(grep -sE '^Net-Name:' $temp/pwhois)"); porg=$(f_VALUE ":" "$(grep -sE '^Org-Name:' $temp/pwhois)")
  if [ "$pnet" != "$porg" ]; then
    echo "$porg"
  else
    [[ -f $temp/geo.json ]] || f_VALUE ":" "$(grep -sE '^AS-Org-Name:' $temp/pwhois)"
  fi
fi
}

f_pwhoisBULK(){
local s="$*" ; echo -e "begin" > $temp/addr.list; cat ${s} >> $temp/addr.list
echo "end" >> $temp/addr.list ; $NCAT whois.pwhois.org 43 < $temp/addr.list > $temp/addr.txt
if [ $domain_enum = "true" ]; then
  grep -E "^IP:|Origin-AS:|^Prefix:|^Org-Name:|^Net-Name:" $temp/addr.txt | sed 's/^[ \t]*//;s/[ \t]*$//' |
  tr '[:space:]' ' ' | sed 's/IP:/\n\n/g' | sed 's/Origin-AS:/|/g' | sed 's/Prefix:/|/g' | sed 's/Org-Name:/|/g' |
  sed 's/Net-Name:/|/g' | sed 's/^ *//' > $temp/pwhois
  [[ -f $temp/pwhois ]] && echo '' >> $temp/pwhois
else
  echo ''; f_Long
  grep -sEa "^IP:|^Origin-AS:|^Prefix:|^AS-Org-Name:|^Org-Name:|^Net-Name:|^Geo-CC:|^Country-Code:" $temp/addr.txt | sed 's/IP: /nnn/' |
  sed 's/Origin-AS:/ - AS/' | sed 's/Prefix:/|/' | sed 's/AS-Org-Name:/| AS ORG__/' | sed 's/Org-Name:/| Org__/' | sed 's/Net-Name:/| NET__/' |
  sed 's/Country-Code:/|/' | sed 's/Geo-CC:/|/' | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' | sed 's/nnn/\n\n/g' |
  sed 's/|/\n\n/' | sed 's/__/:/g' | sed 's/^ *//'; echo ''
fi
}

f_PWHOIS_ORG(){
$TOUT 20 $WHOIS -h whois.pwhois.org registry org-id="$1" | grep ':' > $temp/pwhois_org
pwhois_id=$(grep -saEv "DUMY-RIPE|Dummy|RIPE-NCC-HM-MNT|RIPE-NCC-LEGACY-MNT|RIPE-NCC-END-MNT|Placeholder|\+31 20 535 4444" $temp/pwhois_org |
grep -sEa "^Org-ID:|^Org-Name:|^Source:|^Street(-1)?:|^Street(-2)?:|^City:|^State:|^Postal-Code:|^Country:|^NOC-0-Handle:|^NOC-0-Phone:|^NOC-0-Email:|^ABUSE5232-ARIN|^Abuse-0-Name:|Abuse-0-Phone:|Abuse-0-Email:" | sed '/Org-ID:/i nnn' | sed '/Org-Name:/i nnn' | sed '/Source:/a )' |
sed '/Source:/i (' | sed '/Street-1/i nnn' | sed '/Street:/i nnn' | sed '/Country/i |' | sed '/NOC-0-Handle:/i nnn NOC~' |
sed '/Abuse-0-Name:/i nnn ABUSE~' | sed '/City:/i |' | sed '/Abuse-0-Name:/d' | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' |
tr '[:space:]' ' ' | sed 's/nnn/\n\n/g' | sed 's/^ *//' | sed 's/NOC~/  NOC:  /' | sed 's/ABUSE~/  ABUSE:/' | sed 's/( / (/' | sed 's/ )/) /'; echo '')
[[ -n "$pwhois_id" ]] && echo -e "$pwhois_id\n"
}

f_PWHOIS_ORG_NAME(){
$TOUT 20 $WHOIS -h whois.pwhois.org registry org-name="$1" | grep ':' > $temp/pwhois_name
pwhois_name=$(grep -saEv "DUMY-RIPE|RIPE-NCC-HM-MNT|RIPE-NCC-LEGACY-MNT|RIPE-NCC-END-MNT|Placeholder" $temp/pwhois_name |
grep -sEa "^Org-(ID:|Name:)|^Source:|^Country:|^NOC-0-Handle|^Abuse-0-Handle:|^Abuse-0-Email:|^Admin-0-Handle:|^Tech-0-Handle:" |
tr '[:space:]' ' ' | sed 's/Org-ID:/\n\nID:/g' | sed 's/Org-Name:/|/g' | sed 's/Source:/|/' | sed 's/Country:/|/' | sed 's/NOC-0-Handle:/| MNT:/g' |
sed 's/Abuse-0-Handle:/| ABUSE:/g' | sed 's/Admin-0-Handle:/| ADMIN:/g' | sed 's/Tech-0-Handle:/| TECH:/g' | sed 's/Abuse-0-Email: //' |
sort -bifu | sed 's/| /\n\n/' | sed 's/^ID:/\n\nID:/'; echo '')
if [ -n "$pwhois_name" ]; then
  echo -e "$pwhois_name\n"
  orgs_raw=$(grep -sEa "^Org-(ID:|Name:)" $temp/pwhois_name | sed '/Org-ID:/i ==' | sed '/Org-ID:/a |' |
  cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' | sed 's/==/\n\n/g'; echo '')
  orgs_filtered=$(echo -e "$orgs_raw" | grep -sEi "\b$1\b|\b$1-.*|*.-$1\b" | cut -d '|' -f 1 | sed 's/^[ \t]*//;s/[ \t]*$//' | sort -u)
  if [ -n "$orgs_filtered" ] && [[ $(f_countW "$orgs_filtered") -lt 8 ]]; then
    while read line; do
      f_netBLOCKS "$line"
    done <<< $orgs_filtered
  fi
fi
}

f_netBLOCKS(){
v4_blocks=$($WHOIS -h whois.pwhois.org "netblock org-id=$1" | grep '|' | cut -d '|' -f 1,2,8 | sed '/Net-Range/{x;p;x;G}')
if [ -n "$v4_blocks" ]; then
  f_HEADLINE3 "[PWHOIS]   $1   NETBLOCKS   -  $file_date"
  f_PWHOIS_ORG "$1" && echo ''
  echo -e "\n$v4_blocks\n"
  blockranges=$(echo "$v4_blocks" | grep '*>' | awk '{print $2 $3 $4}')
  if [[ $(f_countW "$blockranges") -lt 500 ]]; then
    for b in $blockranges; do $IPCALC "$b" | sed '/deaggregate/d' | sed '/^$/d'; done > $temp/blockranges
    block_count=$(wc -w < $temp/blockranges)
    if [[ $block_count -gt 0 ]]; then
      echo ''; [[ $block_count -gt 3 ]] && f_Medium
      cat $temp/blockranges | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -w 70
    fi
  fi
fi
}

f_WHOIS_TABLE(){
[[ -f $temp/pwhois_response ]] && rm $temp/pwhois_response; echo -e "begin\ntype=cymru" > $temp/addr.list
f_EXTRACT_IP4 "$1" >> $temp/addr.list; echo 'end' >> $temp/addr.list
$NCAT whois.pwhois.org 43 < $temp/addr.list > $temp/pwhois_response
sed '/Bulk mode; one IP/d' $temp/pwhois_response > $temp/whois_table.txt
cut -s -d '|' -f -5 $temp/whois_table.txt
if [ $target_type != "dnsrec" ] && [ $target_type != "domain" ] && [ -f $temp/whois_table.txt ]; then
  grep 'ORG NAME' $temp/whois_table.txt | cut -s -d '|' -f 1,6 | sed '/AS ORG NAME/{x;p;x;}' > $temp/as_table
  grep -Ev "^Bulk mode|ORG NAME" $temp/whois_table.txt | cut -s -d '|' -f 1,6 | sort -ug -t '|' -k 1 >> $temp/as_table
  [[ $domain_enum = "true" ]] || cat $temp/as_table
fi
}

# -------------------------------------  PRINT WHOIS OUTPUT (WHOIS -F)   -------------------------------------

f_printWHOIS_TARGET(){
local f="$*"
grep -E "^in:|^i6:|^na:|^de:|^cy:|^ac:|^og:|^mb:" $f | sed 's/in:/nnn/g' | sed 's/i6:/nnn/g' | sed '/na:/a )' |
sed 's/na:/(/' | sed 's/de:/de~/' | sed 's/cy:/|/' | sed 's/mb:/|/' | sed 's/ac:/admin~/' | sed 's/og:/og~/' |
sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' | sed 's/nnn/\n\n\n/g' | sed 's/de~/\n\n/' | sed 's/de~//g' |
sed 's/admin~/| Admin:/' | sed 's/admin~//g' | sed 's/og~/| Org:/' | sed 's/og~//g' | sed 's/|/\n\n/' | sed 's/^ *//' |
sed 's/( / (/' | sed 's/ )/)/' | sed '/./,$!d'; echo ''
}

# -------------------------------------  RIPESTSTAT SEARCH COMPLETE  -------------------------------------

f_SEARCH_COMPLETE(){
curl -s --location --request GET "https://stat.ripe.net/data/searchcomplete/data.json?resource=$1" > $temp/search.json
if [ -f $temp/search.json ]; then
  suggest_asns=$($JQ '.data.categories[] | select ( .category == "ASNs" ) | .suggestions[] | {ASN: .value, NAME: .description}?' $temp/search.json |
  sed 's/",//' | tr -d '{"}' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' | tr '[:space:]' ' ' | sed 's/ASN: /\n/g' | sed 's/NAME:/-/g' |
  sed 's/AS/AS /'; echo '')
  suggest_domains=$(jq -r '.data.categories[] | select ( .category == "Domains" ) | .suggestions[].value?' $temp/search.json)
fi
if [ -n "$suggest_asns" ] || [ -n "$suggest_domains" ]; then
  f_HEADLINE3 "RIPESTAT SEARCH COMPLETE SUGGESTIONS"
  [[ -n "$suggest_asns" ]] && echo -e "\n\nASNs\n\n$suggest_asns"
  [[ -n "$suggest_domains" ]] && echo -e "\n\nDomains\n\n$suggest_domains"
fi
}

# -------------------------------------  QUERY HOST INFORMATION  -------------------------------------

f_getHostInfo(){
[[ -f $temp/abx ]] && rm $temp/abx; [[ -f $temp/shodan.json ]] && rm $temp/shodan.json
f_getRIR "$1"; [[ $target_type = "default" ]] && f_get_RIPESTAT_WHOIS "$1"; f_GEO "$1"; f_getABUSE_C "$1"
[[ $1 =~ $REGEX_IP4 ]] && [[ $target_type != "hop" ]] &&  $CURL  -s -m 20 "https://internetdb.shodan.io/$1" > $temp/shodan.json
[[ $target_type = "hop" ]] && timeout 20 $WHOIS -h whois.pwhois.org $1 > $temp/pwhois
[[ $target_type = "default" ]] && f_getPFX "$1" | cut -s -d '|' -f -4 | head -1 > $temp/pfx_tmp
}

f_GEO(){
[[ -f $temp/geo.json ]] && rm $temp/geo.json
$CURL -sL -m 7 "http://ip-api.com/json/$1?fields=54750751" > $temp/geo.json
if [ "$($JQ '.status' $temp/geo.json)" = "success" ]; then
  city=$( $JQ '.city' $temp/geo.json)
  geo_country=$($JQ '.country' $temp/geo.json | sed 's/United States/US/' | sed 's/United Kingdom/UK/')
  [[ $target_type = "default" ]] && regio=$($JQ '.regionName' $temp/geo.json) || regio=$($JQ '.region' $temp/geo.json)
  [[ "$regio" = "$city" ]] && ipapi_out="$city, $geo_country" || ipapi_out="$city, $regio, $geo_country"
fi
 if [ $target_type = "hop" ]; then
  pwhois_geo=$(grep -E -m1 "^Country-Code:|^Geo-CC:" $temp/pwhois | awk '{print $NF}' | tr -d ' ')
  echo "$ipapi_out | pwhois: $pwhois_geo" > $temp/geo
elif [ $target_type = "default" ]; then
  geoplugin_out=$($CURL -sL -m 7 "http://www.geoplugin.net/json.gp?ip=$1" | jq -r '.geoplugin_countryCode') 
  echo "$ipapi_out; $geoplugin_out" > $temp/geo
else
  echo "$ipapi_out" > $temp/geo
fi
}

f_getABUSE_C(){
if [ $target_type = "default" ] && [ $rir = "lacnic" ]; then
  $WHOIS -h whois.lacnic.net $1 > $temp/whois; f_printLACNIC_ABUSE_C "$temp/whois" > $temp/abx
else
  if [ $rir != "lacnic" ]; then
    rev=$(f_REVERSE "$1")
    $DIG +short $rev.abuse-contacts.abusix.zone txt | tr -d '"' | grep '@' | grep -v 'lacnic' | sed 's/^[ \t]*//;s/[ \t]*$//' > $temp/abx
    if [ ! -f $temp/abx ]; then
      $CURL -m 5 -s "https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=$1" | $JQ '.data.abuse_contacts[]?' > $temp/abx
    fi
  fi
fi
}

f_getCPES(){
if [ -f $temp/shodan.json ]; then
  cpes=$($JQ '.cpes[]?' $temp/shodan.json | sed 's/^cpe:\///' | sort | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//')
  [[ -n "$cpes" ]] && echo "$cpes"
fi
}

f_getCVES(){
if [ -f $temp/shodan.json ]; then
  cves=$($JQ '.vulns[]?' $temp/shodan.json); [[ -n "$cves" ]] && echo "$cves" | tr '[:space:]' ' ' | fmt -w 70
fi
}

f_getHOSTNAMES(){
[[ -f $temp/hostnames ]] && rm $temp/hostnames
[[ -f $temp/shodan.json ]] && $JQ '.hostnames[]?' $temp/shodan.json | sort > $temp/hostnames
if [ -f $temp/hostnames ] && [[ $(cat $temp/hostnames | wc -w) -gt 0 ]]; then
  if [ $target_type = "net" ] && [ $target_type = "other" ]; then
    head -15 $temp/hostnames | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/ /  /g' | sed 's/^ *//' | fmt -w 100; echo ''
  else
    cat $temp/hostnames | tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/ /  /g' | sed 's/^ *//' | fmt -w 70; echo ''
  fi
fi
}

f_getHOST_SERVICES(){
[[ -f $temp/tags ]] && rm $temp/tags; unset detected_ports; unset print_ports; unset shodan_cpes
if [[ $1 =~ $REGEX_IP4 ]]; then
  if [ -f $temp/shodan.json ]; then
    detected_ports=$($JQ '.ports[]?' $temp/shodan.json | grep [0-9])
    if [ -n "$detected_ports" ]; then
      print_ports=$(echo "$detected_ports" | tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//')
      echo "$detected_ports" >> $temp/detected_ports; [[ $target_type = "default" ]] || shodan_cpes=$(f_getCPES)
    else
      print_ports="unknown"
    fi
    $JQ '.tags[]?' $temp/shodan.json > $temp/tags;
    f_TOR "$1" | grep 'true' | grep -o 'TOR' >> $temp/tags
  fi
else
  v6_info=$(f_IPV6_INFO "$1"); [[ -n "$v6_info" ]] && echo "$v6_info" > $temp/tags
fi
if [ -f $temp/geo.json ]; then
  $JQ '.proxy' $temp/geo.json | grep -o 'true' | sed 's/true/proxy/' >> $temp/tags
  $JQ '.mobile' $temp/geo.json | grep -o 'true' | sed 's/true/mobile/' >> $temp/tags
  $JQ '.hosting' $temp/geo.json | grep -o 'true' | sed 's/true/hosting/' >> $temp/tags
fi
[[ -f $temp/tags ]] && [[ $(wc -w < $temp/tags) -gt 0 ]] && f_toUPPER "$(sort -u $temp/tags)" > $temp/addr_info
if [ -n "$print_ports" ]; then
  [[ -f $temp/addr_info ]] && echo "| Ports: $print_ports" >> $temp/addr_info || echo "Ports: $print_ports" > $temp/addr_info
fi
if [[ $1 =~ $REGEX_IP4 ]] && [ $target_type != "default" ] && [ -n "$shodan_cpes" ]; then
  print_cpes=$(echo "$shodan_cpes" | tr '[:space:]' ' ')
  [[ $(wc -w <<<$print_cpes) -gt 2 ]] && echo "___$print_cpes" >> $temp/addr_info || echo "| $print_cpes" >> $temp/addr_info
fi
[[ -f $temp/addr_info ]] && cat  $temp/addr_info | tr '[:space:]' ' ' | sed 's/___/\n\n/g' | sed 's/^ *//' && echo '' && rm $temp/addr_info
}

f_IPV6_INFO(){
local h="$*"; [[ -f $temp/v6info ]] && rm $temp/v6info
$NMAP -6 -sn -Pn $h --script address-info.nse 2>/dev/null | grep -E "^\|" | tr -d '|_' | sed 's/^ *//' |
grep -E "address:|IPv4|IPv6|MAC|manuf|ISATAP|UDP|6to4" | sed 's/IPv4 address:/| IPv4:/' | sed 's/MAC address: /| MAC/' |
sed 's/IPv6 [Aa]ddress:/IPv6 Addr/' | sed 's/IPv6 EUI-64: /EUI-64/' | sed 's/^[ \t]*//;s/[ \t]*$//' |
tr '[:space:]' ' ' | sed 's/MAC address:/MAC:/' > $temp/v6info
[[ -f $temp/v6info ]] && cat $temp/v6info | tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//' && echo ''
}

# -------------------------------------  PRINT HOST INFORMATION  -------------------------------------

f_CVES(){
[[ -f $temp/shodan.json ]] && rm $temp/shodan.json
$CURL -s -m 5 "https://internetdb.shodan.io/$1" > $temp/shodan.json
if [ -f $temp/shodan.json ]; then
  [[ -f $temp/tags ]] && rm $temp/tags
  unset print_tags; unset shodan_ports; unset shodan_cves; unset vulners
  shodan_ports=$($JQ '.ports[]?' $temp/shodan.json | sed '/null/d')
  if [ -n "$shodan_ports" ]; then
    echo "$shodan_ports" >> $temp/net_ports; hostn=$(f_getHOSTNAMES); f_TOR "$1" | grep 'true' | grep -o 'TOR' > $temp/tags
    print_ports=$(echo "$shodan_ports" | tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//')
    $JQ '.tags[]?' $temp/shodan.json | sed 's/cloud/Cloud/' | sed 's/vpn/VPN/' |
    sed 's/starttls/StartTLS/' | sed 's/database/Database/' | sort -u >> $temp/tags
    shodan_cpes=$(f_getCPES) && shodan_cves=$(f_getCVES)
    [[ -n "$shodan_cves" ]] && vulners="$shodan_cves" || vulners="-"
    [[ -n "$print_tags" ]] && echo -e "\n\n>  $1  ($print_tags)" || echo -e "\n\n>  $1"
    if [ -n "$shodan_cpes" ]; then
      if [[ $(wc -w <<<$shodan_cpes) -lt 4 ]]; then
        echo -e "\n+  Ports:  $print_ports  | CPEs: $shodan_cpes"
      else
        echo -e "\n+  Ports:  $print_ports"; echo -e "\n+  CPEs:   $shodan_cpes"
      fi
    else
      echo -e "\n+  Ports:  $print_ports"
    fi
    [[ -n "$hostn" ]] && echo -e "\n$hostn" | sed 's/^/   /'
    [[ -n "$shodan_cves" ]] && echo -e "\n   ! VULNS !\n" && echo -e "$vulners" | sed 's/^/   /'; echo ''
  else
    [[ $target_type != "net" ]] && echo -e "\n\n>  $1\n\n!  No data for open ports, services & CVEs\n"
  fi
else
  [[ $target_type != "net" ]] && echo -e "\n\n>  $1\n\n   No response\n"
fi
}

f_HOP(){
unset tor_node; unset tor_message; echo ''; f_BOGON "$1"
if [ $bogon = "TRUE" ]; then
  f_BOGON_INFO "$1"; echo "$1" >> $temp/hops_bogon
else
  echo "$1" >> $temp/hops_public
  [[ -f $temp/whois_records ]] && rm $temp/whois_records
  [[ -f $temp/pwhois ]] && rm $temp/pwhois; f_getHostInfo "$1"
  if [[ $(grep -sEc "^Origin-AS:" $temp/pwhois) -gt 0 ]]; then
    prefix=$(grep -sE -m 1 "^Prefix:" $temp/pwhois | awk '{print $NF}' | tr -d ' ')
    pfx_spamhaus_listed=$(grep -sw "$prefix" ${file_date}.ip_drop.txt)
    asn=$(grep -sE -m 1 "^Origin-AS:" $temp/pwhois | awk '{print $NF}' | tr -d ' ')
    $CURL -s -m 5 --location --request GET "https://stat.ripe.net/data/rpki-validation/data.json?resource=$asn&prefix=$prefix" > $temp/rpki.json
    rpki_status=$($JQ '.data.status?' $temp/rpki.json); mobile_net=$($JQ '.mobile' $temp/geo.json | grep 'true' | sed 's/true/ | MOBILE/')
    [[ $1 =~ $REGEX_IP4 ]] && tor_node=$(f_TOR "$1" | grep 'true') || tor_node=''
    [[ -n "$tor_node" ]] && tor_message="| TOR !"; [[ $rir = "lacnic" ]] || f_getABUSE_C "$1"
    if [[ $1 =~ $REGEX_IP46 ]]; then
      hop_rdns=$($DIG +short -x $1 | rev | cut -d ' ' -f 1 | cut -c 2- | rev)
        if [ -n "$hop_rdns" ]; then
          [[ $target_cat = "host4" ]] && ip_alt=$($DIG +short aaaa "$hop_rdns") || ip_alt=$($DIG +short a "$hop_rdns")
        fi
        [[ -n "$ip_alt" ]] && print_alt="($(echo "$ip_alt" | head -2 | tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//'))"
    fi
    [[ -n "$asn" ]] && type_indicator="[$asn]" || type_indicator="[HOP]"
    if [ -n "$hop_count" ]; then
      f_HEADLINE3 "$type_indicator   HOP: $hop_count  RTT: $rtt  |  $1  |  ROA: $rpki_status  $mobile_net $tor_node"
    else
      f_HEADLINE3 "$type_indicator  HOP: ?  |  $1  |  ROA: $rpki_status   $mobile_net $tor_node"
    fi
    [[ $rir = "lacnic" ]] && echo -e "Geo:  $(cat $temp/geo)\n___\n" || f_printABUSE_C
    [[ -n "$hop_rdns" ]] && echo -e "\nrDNS:         $hop_rdns  $print_alt"
    if ! [[ $1 =~ $REGEX_IP4 ]]; then
      v6_info=$(f_IPV6_INFO "$1"); [[ -n "$v6_info" ]] && echo -e "\nAddr.Type:     $v6_info"
    fi
    f_getASNAME "$asn"; echo ''
    if [ $rir = "lacnic" ]; then
      echo -e "\nBGP:          *>  $prefix  (LACNIC)"
    else
      netname=$(grep -sE -m 1 "^Net-Name:" $temp/pwhois | awk '{print $NF}' |  tr -d ' ')
      echo -e "\nBGP:          *>  $prefix  | $netname | $(f_toUPPER "$rir")"
    fi
      [[ -n "$pfx_spamhaus_listed" ]] && echo -e "\nSpamhaus:     ! Prefix listed in DON'T ROUTE OR PEER !\n"
      vis=$(f_VIS "$prefix"); echo -e "\nRIS:          $vis"
  else
    f_get_RIPESTAT_WHOIS "$1"; ix_host=$(f_IX_HOST "$1")
    if [ -n "$ix_host" ]; then
      echo "$ix_host"; [[ $rir = "lacnic" ]] && $WHOIS -h whois.lacnic.net $1 > $temp/whois; echo ''; f_NET_SHORT "$1";
    fi
  fi
fi
}

f_HOST_DEFAULT(){
rev_dns=""
if [ $bogon = "TRUE" ] ; then
  f_BOGON_INFO "$1"
else
  f_getHostInfo "$1"; asn=$(cut -d '|' -f 1 $temp/pfx_tmp | tr -d ' ')
  [[ -z "$asn" ]] && ix_host=$(f_IX_HOST "$1") && [[ -n "$ix_host" ]] && echo "$ix_host" && f_HOST_RDNS "$1" && f_NET_SHORT "$1"
  if [ -z "$ix_host" ]; then
    pfx=$(cut -d '|' -f 2 $temp/pfx_tmp | tr -d ' '); service_info=$(f_getHOST_SERVICES "$1")
    geo_cc=$($JQ '.countryCode' $temp/geo.json); offset=$(($($JQ '.offset' $temp/geo.json) / 3600))
    if [[ $1 =~ $REGEX_IP4 ]]; then
      shodan_cpes=$(f_getCPES); shodan_cves=$(f_getCVES); hostn=$(f_getHOSTNAMES)
      tor_node=$(f_TOR "$1" | grep 'true'); [[ -n "$tor_node" ]] && tor_message=" |  TOR NODE " || tor_message=""
    else
      tor_message=""
    fi
    f_HEADLINE3 "[HOST]  $1  | $geo_cc (UTC $offset H) $tor_message |  $file_date"; f_printABUSE_C
    rdns=$(f_HOST_DNS "$1"); [[ -n "$rdns" ]] || rdns="no PTR record" 
    echo -e "\nrDNS:         $rdns"
    [[ -n "$service_info" ]] && echo -e "\nServices:     $service_info"
    if [[ $1 =~ $REGEX_IP4 ]]; then
      [[ -n "$shodan_cpes" ]] && [[ $(f_countW "$shodan_cpes") -lt 4 ]] && echo -e "\nCPEs:         $shodan_cpes"
      [[ -n "$hostn" ]] && [[ $(f_countW "$hostn") -lt 4 ]] && echo -e "\nHostnames:    $hostn"
    fi
    echo -e "\n"; f_NET_SHORT "$1"; f_printAUTH_NS
    if [[ $1 =~ $REGEX_IP4 ]]; then
      [[ $(f_countW "$shodan_cpes") -gt 3 ]] && f_HEADLINE4 "CPES\n" && echo -e "$shodan_cpes" | fmt -w 70 | sed G
      [[ -n "$shodan_cves" ]] && f_HEADLINE4 "VULNERS\n" && echo -e "$shodan_cves\n\n(SOURCE: SHODAN)"
      [[ $(f_countW "$hostn") -gt 3 ]] && f_HEADLINE4 "HOSTNAMES\n" && echo "$hostn" | sed G
      [[ -f $temp/rdns ]] && f_HEADLINE4 "DNS\n" && cat $temp/rdns
      if [ $threat_enum = "true" ]; then
       [[ $opt_rep2 = "y" ]] && f_VHOSTS "$1"
       f_Long && f_IP_REPUTATION "$1"
      fi
    fi
    [[ $option_detail = "2" ]] && f_ROUTE_CONS "$pfx"
  fi
fi
}

f_HOST_SHORT(){
shodan_cpes=""; shodan_cves=""; hostnames=""; services_v6=""; print_rdns=""
f_BOGON "$1"
if [ $bogon = "TRUE" ]; then
  echo ''; f_BOGON_INFO "$1"
else
  if [ $domain_enum = "true" ] || [ $target_type = "domain" ]; then
    $CURL -s -m 10 --location --request GET "https://stat.ripe.net/data/reverse-dns-ip/data.json?resource=$1" > $temp/rdns.json
    rdns=$($JQ '.data.result[]?' $temp/rdns.json)
    [[ -n "$rdns" ]] && print_rdns="  -  $rdns" || print_rdns=""
  fi
  f_getHostInfo "$1"; service_info=$(f_getHOST_SERVICES "$1"); [[ $1 =~ $REGEX_IP4 ]] && shodan_cves=$(f_getCVES)
  [[ -f $temp/abx ]] && abu=$(f_EXTRACT_EMAIL "$temp/abx" | tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//')
  offset=$(($($JQ '.offset' $temp/geo.json) / 3600)); org=$($JQ '.org' $temp/geo.json)
  [[ -z "$org" ]] && org=$($JQ '.isp' $temp/geo.json); ip_geo=$(cat $temp/geo)
  if [[ $1 =~ $REGEX_IP4 ]]; then
    if [ $target_type = "web" ] || [ $target_type = "hostname" ] || [ $target_type = "domain" ]; then
      f_HEADLINE2 "*  $1\n"
    else
      echo -e "\n*  $1 $print_rdns\n"
    fi
  else
   echo -e "\n\n*  $1 $print_rdns\n"
  fi
  [[ -n "$abu" ]] && host_sum="$ip_geo (UTC $offset) | $org | $abu" || host_sum="$ip_geo (UTC $offset) | $org"
  [[ $1 =~ $REGEX_IP6 ]] && [[ $(f_countW "$service_info") -gt 0 ]] && services_v6="$service_info"
  if [ $target_type = "web" ]; then
    echo -e "$host_sum\n"; [[ -n "$services_v6" ]] && echo -e "$services_v6\n"
  else
    echo -e ">  $host_sum\n"; [[ -n "$services_v6" ]] && echo -e "  $services_v6\n"
  fi
  if [ $target_type != "dnsrec" ] || [ $domain_enum = "false" ]; then
    f_ROUTE "$1"
  fi
  if [[ $1 =~ $REGEX_IP4 ]]; then
    if [ $target_type = "dnsrec" ] || [ $target_type = "domain" ]; then
      echo -e "$service_info" | sed 's/^/   /'
    else
      echo -e "\nSERVICES:\n\n$service_info\n"
    fi
    if [ $target_type = "web" ] || [ $target_type = "hostname" ]; then
      f_Medium; echo -e "VULNERS (SOURCE: SHODAN)\n"
      [[ $(f_countW "$shodan_cves") -gt 0 ]] && echo -e "\n$shodan_cves" || echo "No CVEs found"; f_Medium
      f_IP_REPUTATION "$1" | sed '/^$/d' | sed '/IP REPUTATION/G'
    else
      [[ $(f_countW "$shodan_cves") -gt 0 ]] && echo -e "\n!  VULNERS (Shodan):\n" && echo -e "$shodan_cves\n" | sed 's/^/   /'
    fi
    if [ $target_type = "hostname" ] || [ $target_type = "domain" ]; then
      hostnames=$(f_getHOSTNAMES); [[ -n "$hostnames" ]] && f_Medium && echo -e "HOSTNAMES\n\n$hostnames\n"
    fi
  fi
fi
}

f_IX_HOST(){
if [ $rir = "arin" ]; then
  check_ixlan=0
  try_cidrs=$($JQ '.data.records[]? | .[] | select (.key=="CIDR") | .value' $temp/whois.json | grep -sEo "$IP4_NET_ALT|$REGEX_NET6")
   for c in $try_cidrs; do
      check_ixlan=$(grep -w -c "$c" ${PWD}/${file_date}.ix_pfx.txt)
      [[ $check_ixlan -gt 0 ]] && grep -m 1 -A 1 "$c" ${PWD}/${file_date}.ix_pfx.txt | tail -1 | tr -d ' ' > $temp/ixid || check_ixlan=0
   done
   [[ -f  $temp/ixid ]] && ixlid=$(grep -sEo -m 1 "[0-9]{1,3}" $temp/ixid)
else
  ixlan=$(f_getNET_RANGE "$1")
  [[ -n "$ixlan" ]] && ixlid=$(grep -m 1 -A 1 "$ixlan" ${PWD}/${file_date}.ix_pfx.txt | tail -1 | tr -d ' ')
fi
if [ -n "$ixlid" ]; then
  $CURL -s "https://www.peeringdb.com/api/ix/${ixlid}" > $temp/ixlan.json
  f_getABUSE_C "$1"; abuse_mbox=$(sort -u $temp/abx | tr '[:space:]' ' ')
  ix_name=$($JQ '.data[0].name' $temp/ixlan.json); ix_cc=$($JQ '.data[0].org.country' $temp/ixlan.json)
  ix_city=$($JQ '.data[0].city' $temp/ixlan.json); ix_mail=$($JQ '.data[0].tech_email' $temp/ixlan.json)
  ix_phone=$($JQ '.data[0].tech_phone' $temp/ixlan.json)
  [[ $target_type = "hop" ]] && f_HEADLINE3 "[IX]  HOP: $hop_count  RTT: $rtt |  $1  |  $ix_name" || f_HEADLINE3 "[HOST]  IX - $1 | $ix_name  ($file_date)"
  echo -e "[@]: $abuse_mbox\n"; echo -e "\nGeo:          $ix_city, $ix_cc"; echo -e "\nContact:      $ix_mail  $ix_phone\n"
fi
}

f_printABUSE_C(){
ip_geo=$(cat $temp/geo); abuse_mbox=$(f_EXTRACT_EMAIL "$temp/abx" | tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//')
mail_count=$(f_countW "$abuse_mbox")
if [[ $mail_count -gt 0 ]]; then
  [[ $mail_count -gt 2 ]] && echo -e "[@]:  $abuse_mbox\n\nGEO:  $ip_geo\n___\n" || echo -e "[@]:  $abuse_mbox  |  $ip_geo\n___\n"
else
  echo -e "[@]:  NA  |  $ip_geo\n___\n"
fi
}

# -------------------------------------  DOWNLOAD THREAD FEEDS  -------------------------------------

f_getDROPLISTS(){
if ! [ -f ${file_date}.asndrop.json ]; then
  echo -e "\nDownloading spamhaus.org Don't Route Or Peer Lists ...\n"
  $CURL -sL -m 50 "https://www.spamhaus.org/drop/asndrop.json" > ${file_date}.asndrop.json
fi
if ! [ -f ${file_date}.ipv4_drop.txt ]; then
  $CURL -sL -m 50 "https://www.spamhaus.org/drop/drop.txt" > ${file_date}.ipv4_drop.txt
  $CURL -sL -m 50 "https://www.spamhaus.org/drop/edrop.txt" >> ${file_date}.ipv4_drop.txt
fi
if ! [ -f ${file_date}.ipv6_drop.txt ]; then
  $CURL -sL -m 50 "https://www.spamhaus.org/drop/dropv6.txt" > ${file_date}.ipv6_drop.txt
fi
[[ -f ${file_date}.ipv4_drop.txt ]] && f_EXTRACT_NET4 "${file_date}.ipv4_drop.txt" > ${file_date}.ip_drop.txt
[[ -f ${file_date}.ipv6_drop.txt ]] && f_EXTRACT_NET6 "${file_date}.ipv6_drop.txt" >> ${file_date}.ip_drop.txt
[[ -f ${file_date}.asndrop.json ]] && drop_asns=$(jq -r '.asn' ${file_date}.asndrop.json | grep '[0-9]')
if [ -n "$drop_asns" ]; then
  echo "$drop_asns" > ${file_date}.asndrop.list
  jq -r '{ASN: .asn, DOMAIN: .domain}' ${file_date}.asndrop.json | sed '/null/d' | tr -d '{",}' |
  sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' | sed '/DOMAIN:/a )' | tr '[:space:]' ' ' | sed 's/ASN:/\n\nAS__/g' |
  sed 's/DOMAIN:/(/' | tr -d ' ' | sed 's/(/ (/' | sed 's/__/ /' > ${file_date}.asndrop.txt
  echo '' >> ${file_date}.asndrop.txt
fi
}

f_getTHREAT_FEEDS_IP(){
if ! [ -f ${file_date}.ci.txt ]; then
  echo -e "\nDownloading CI Army CINS Blockist..."
  $CURL -m 50 -sL "http://cinsscore.com/list/ci-badguys.txt" |
  grep -v "#" | grep -sEo "$IP4_ALT" > ${file_date}.ci.txt
fi
if ! [ -f ${file_date}.feodo.txt ]; then
  echo -e "Downloading Feodotracker botnet & C2 list ..."
  $CURL -m 50 -sL "https://feodotracker.abuse.ch/downloads/ipblocklist.txt" |
  grep -v "#" | grep -sEo "$IP4_ALT" >  ${file_date}.feodo.txt
fi
if ! [ -f ${file_date}.alienvault.txt ]; then
  echo -e "Downloading Alienvault Generic IP Reputation List ..."
  $CURL -sL "https://reputation.alienvault.com/reputation.generic" | grep -v "#" | grep -sEo "$IP4_ALT" > ${file_date}.alienvault.txt
fi
if ! [ -f ${file_date}.monero_ips.txt ]; then
  echo -e "Downloading rblaine95's Monero Pool IP Blocklist ..."
  $CURL -sL -m 50 "https://github.com/rblaine95/monero-banlist/blob/master/block.txt" |
  grep -v "#" | grep -sEo "$IP4_ALT" > ${file_date}.monero_ips.txt
fi
if ! [ -f ${file_date}.rescure_ips.txt ]; then
  $CURL -sL -m 50 "https://rescure.me/rescure_blacklist.txt" | grep -v "#" | grep -sEo "$IP4_ALT" > ${file_date}.rescure_ips.txt
fi
[[ $opt2 = "y" ]] && f_getTHREAT_FEEDS_DOMAIN
}

f_getTHREAT_FEEDS_DOMAIN(){
if ! [ -f ${file_date}.pegasus.txt ] || ! [ -f ${file_date}.cytrox.txt ] || ! [ -f ${file_date}.android_campaign.txt ]; then
  echo -e "\nDownloading Spyware IOCs from Amnesty Tech ..."
  $CURL -sL -m 50 "https://raw.githubusercontent.com/AmnestyTech/investigations/master/2021-07-18_nso/domains.txt" > $temp/nso
  $CURL -sL -m 50 "https://raw.githubusercontent.com/AmnestyTech/investigations/master/2021-12-16_cytrox/domains.txt" > $temp/cytrox
  $CURL -sL -m 50 "https://raw.githubusercontent.com/AmnestyTech/investigations/master/2023-03-29_android_campaign/domains.txt" > $temp/android_campaign
  [[ -f $temp/nso ]] && f_EXTRACT_HOSTN "$(grep -v '#' $temp/nso)" > ${file_date}.pegasus.txt
  [[ -f $temp/cytrox ]] && f_EXTRACT_HOSTN "$(grep -v '#' $temp/cytrox)" > ${file_date}.cytrox.txt
  [[ -f $temp/android_campaign ]] && f_EXTRACT_HOSTN "$temp/android_campaign" > ${file_date}.android_campaign.txt
fi
if ! [ -f ${file_date}.urlhaus_malware.txt ]; then
  echo -e "Downloading URLHaus Malware Filter ..."
  $CURL -sL -m 50 "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts-online.txt" > $temp/urlhaus
  [[ -f $temp/urlhaus ]] && f_EXTRACT_HOSTN "$(grep -v '#' $temp/urlhaus)" > ${file_date}.urlhaus_malware.txt
fi
if ! [ -f ${file_date}.hagezi_domains.txt ]; then
  echo -e "Downloading Domain Threatfeed by Hagezi ..."
  $CURL -sL -m 50 "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/domains/tif.txt" > $temp/hagezi
  [[ -f $temp/hagezi ]] && f_EXTRACT_HOSTN "$(grep -v '#' $temp/hagezi)" > ${file_date}.hagezi_domains.txt
fi
if ! [ -f ${file_date}.hagezi_dyndns.txt ]; then
  echo -e "Downloading DynDNS Threatfeed by Hagezi ..."
  $CURL -sL -m 50 "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/dyndns.txt" > $temp/dyndns
  [[ -f $temp/dyndns ]] && grep  -v '#' $temp/dyndns | tr -d '*' | tr -d ' ' > ${file_date}.hagezi_dyndns.txt
fi
if ! [ -f ${file_date}.openphish.txt ]; then
  echo -e "Downloading Openphish Feed ..."
  $CURL -sL -m 50 "https://openphish.com/feed.txt" > ${file_date}.openphish.txt
  [[ -f ${file_date}.openphish.txt ]] && f_EXTRACT_HOSTN "${file_date}.openphish.txt" > ${file_date}.openphish_hosts.txt
fi
if ! [ -f ${file_date}.phishing_army.txt ]; then
  $CURL -sL -m 50 "https://phishing.army/download/phishing_army_blocklist.txt" > $temp/phish
  [[ -f $temp/phish ]] && f_EXTRACT_HOSTN "$(grep -v '#' $temp/phish)" > ${file_date}.phishing_army.txt
fi
if ! [ -f ${file_date}.rescure_domains.txt ]; then
  $CURL -sL -m 50 "https://rescure.me/rescure_domain_blacklist.txt" | grep -v '#' > $temp/rescure
  [[ -f $temp/rescure ]] && f_EXTRACT_HOSTN "$temp/rescure" > ${file_date}.rescure_domains.txt
fi
if ! [ -f ${file_date}.zonefiles.txt ]; then
  echo -e "Downloading zonefiles compromised/malicious domains list ..."
  $CURL -sL -m 50 "https://zonefiles.io/f/compromised/domains/live/" > $temp/zonefiles
  [[ -f $temp/zonefiles ]] && f_EXTRACT_HOSTN "$(grep -v '#' $temp/zonefiles)" > ${file_date}.zonefiles.txt
fi
}

# -------------------------------------  IP REPUTATION  -------------------------------------

f_BLOCKLIST_CHECK(){
f_BOGON "$1"
if [ $bogon = "TRUE" ] ; then
  f_BOGON_INFO "$1"
else
  f_DNS_BLOCKLIST_CHECK "$1" > $temp/blocklist_check; f_IP_BLOCKLIST_CHECK "$1" >> $temp/blocklist_check
  [[ -f $temp/blocklist_check ]] && sed '/^$/d' $temp/blocklist_check && rm $temp/blocklist_check
fi
}

f_DNS_BLOCKLIST_CHECK(){
[[ -f $temp/rats ]] && rm $temp/rats; [[ -f $temp/sorbs ]] && rm $temp/sorbs
[[ -f $temp/bl_entries ]] && rm $temp/bl_entries; [[ -f $temp/bl_all ]] && rm $temp/bl_all
blde_response="$($DIG +short -t txt $(f_REVERSE "$1").all.bl.blocklist.de.)"
if [ -n "$blde_response" ]; then
  print_blde=$(echo "$blde_response" | tr -d '"' | awk -F'see' '{print $1}' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/,$//')
  echo -e "\n! blocklist.de !      $print_blde" >> $temp/bl_all
fi
sorbs_response="$($DIG +short -t a $(f_REVERSE "$1").dnsbl.sorbs.net.)"
if [ -n "$sorbs_response" ]; then
  [[ $(echo "$sorbs_response" | grep -oc "127.0.0.2") -eq 1 ]] && echo "[open_http_proxy]" >> $temp/sorbs
  [[ $(echo "$sorbs_response" | grep -oc "127.0.0.3") -eq 1 ]] && echo "[open_socks_proxy]" >> $temp/sorbs
  [[ $(echo "$sorbs_response" | grep -oc "127.0.0.4") -eq 1 ]] && echo "[open_proxy]" >> $temp/sorbs
  [[ $(echo "$sorbs_response" | grep -oc "127.0.0.5") -eq 1 ]] && echo "[open_smtp_relay]" >> $temp/sorbs
  [[ $(echo "$sorbs_response" | grep -oc "127.0.0.6") -eq 1 ]] && echo "[spam]" >> $temp/sorbs
  [[ $(echo "$sorbs_response" | grep -oc "127.0.0.7") -eq 1 ]] && echo "[vuln_webserver]" >> $temp/sorbs
  [[ $(echo "$sorbs_response" | grep -oc "127.0.0.8") -eq 1 ]] && echo "[malicious]" >> $temp/sorbs
  [[ $(echo "$sorbs_response" | grep -oc "127.0.0.9") -eq 1 ]] && echo "[zombie]" >> $temp/sorbs
  [[ $(echo "$sorbs_response" | grep -oc "127.0.0.10") -eq 1 ]] && echo "[dynamic_IP]" >> $temp/sorbs
  [[ $(echo "$sorbs_response" | grep -oc "127.0.0.11") -eq 1 ]] && echo "[bad_config]" >> $temp/sorbs
  [[ $(echo "$sorbs_response" | grep -oc "127.0.0.12") -eq 1 ]] && echo "[no_MTA_address_space]" >> $temp/sorbs
  [[ $(echo "$sorbs_response" | grep -oc "127.0.0.14") -eq 1 ]] && echo "[no_server_address_space]" >> $temp/sorbs
  [[ -f $temp/sorbs ]] && sorbs_message=$(cat $temp/sorbs | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/_/ /g' | sed 's/^ *//'; echo '')
  [[ -n "$sorbs_message" ]] && echo -e "\n! SORBS !             $1: $sorbs_message" >> $temp/bl_all
fi
rats_response="$($DIG +short -t a $(f_REVERSE "$1").all.spamrats.com.)"
if [ -n "$rats_response" ]; then
  [[ $(echo "$rats_response" | grep -oc "127.0.0.36") -eq 1 ]] && echo "[abusive_dyn_IP]" >> $temp/rats
  [[ $(echo "$rats_response" | grep -oc "127.0.0.37") -eq 1 ]] && echo "[suspicious_no_PTR]" >> $temp/rats
  [[ $(echo "$rats_response" | grep -oc "127.0.0.38") -eq 1 ]] && echo "[spam]" >> $temp/rats
  [[ $(echo "$rats_response" | grep -oc "127.0.0.43") -eq 1 ]] && echo "[auth._attacks]" >> $temp/rats
  [[ -f $temp/rats ]] && rats_message=$(cat $temp/rats | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/_/ /g' | sed 's/^ *//'; echo '')
  [[ -n "$rats_message" ]] && echo -e "\n! SPAMRATS !          $1: $rats_message" >> $temp/bl_all
fi
for i in $blocklists_other; do
  bl_response="$($DIG +short -t a $(f_REVERSE "$1").${i}.)"
  [[ -n "$bl_response" ]] && echo "$i"
done > $temp/bl_entries
if [ -f $temp/bl_entries ] && [[ $(wc -w < $temp/bl_entries) -gt 0 ]]; then
  print_bl=$(cat $temp/bl_entries | tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/ /  /g'; echo '')
  echo -e "\n! DNS Blocklists !    $print_bl" >> $temp/bl_all
fi
$DIG +short -t txt $(f_REVERSE "$1").tor.dan.me.uk. > $temp/tor_info
tor_node_name=$(f_TOR_NODE); tor_flags=$(f_RELAY_FLAGS)
if [ -n "$tor_node_name" ]; then
  echo -e "\n! tor.dan.me.uk !     Node:  $tor_node_name" >> $temp/bl_all
  echo -e "\n                      Flags: $tor_flags" >> $temp/bl_all
fi
if [ -f $temp/bl_all ] && [[ $(grep -c '!' $temp/bl_all) -gt 0 ]]; then
  cat $temp/bl_all
else
  echo -e "\n+ DNS Blocklists:     not listed"
fi
}

f_GREY_NOISE(){
$CURL -m 10 -sL "https://api.greynoise.io/v3/community/$1" > $temp/gn.json
if [ -f $temp/gn.json ]; then
  gn_ip=$($JQ '.ip' $temp/gn.json); gn_mssg=$($JQ '.message' $temp/gn.json)
  gn_lseen=$($JQ '.last_seen' $temp/gn.json | sed '/null/d')
  if [ -n "$gn_lseen" ]; then
    gn_noise=$($JQ '.noise' $temp/gn.json | sed 's/true/port scanner/' | sed 's/false/no noise/')
    gn_class=$($JQ '.classification' $temp/gn.json); gn_riot=$($JQ '.riot' $temp/gn.json)
    [[ $gn_riot = "true" ]] && riot="| rule-it-out: true" || riot=''
    echo -e "\n! GreyNoise !         $gn_noise | $gn_class | last: $gn_lseen $riot"
  else
    message_out=$(echo "$gn_mssg" | sed 's/IP not observed scanning the internet or contained in RIOT data set./Not observed scanning the internet/')
    echo -e "\n+ GreyNoise:          $message_out"
  fi; rm $temp/gn.json
fi
}

f_IP_BLOCKLIST_CHECK(){
if [ -f ${file_date}.ci.txt ]; then
  [[ $(grep -w -c "$1" $file_date.ci.txt) -gt 0 ]] && echo -e "\n! CI Army !           listed" > $temp/ip_bl
else
  echo -e "\n! CI Army             file missing" > $temp/ip_bl
fi
if [ -f ${file_date}.feodo.txt ]; then
  [[ $(grep -w -c "$1" ${file_date}.feodo.txt) -gt 0 ]] &&  echo -e "\n! FeodoTracker !  botnet/C2 server" >> $temp/ip_bl
else
  echo -e "\n! FeodoTracker        file missing" >> $temp/ip_bl
fi

if [ -f ${file_date}.alienvault.txt ]; then
  [[ $(grep -w -c "$1" ${file_date}.alienvault.txt) -gt 0 ]] && echo -e "\n! AlienVault !     listed" >> $temp/ip_bl
else
  echo -e "\n! AlienVault         file missing" >> $temp/ip_bl
fi
if [ -f ${file_date}.monero_ips.txt ]; then
  [[ $(grep -w -c "$1" ${file_date}.monero_ips.txt) -gt 0 ]] && echo -e "\n! Monero IPs !      Monero Coin Mining Pool" >> $temp/ip_bl
else
  echo -e "\n! Monero IPs         file missing" >> $temp/ip_bl
fi
if [ -f ${file_date}.rescure_ips.txt ]; then
  [[ $(grep -w -c "$1" ${file_date}.rescure_ips.txt) -gt 0 ]] && echo -e "\n! Rescure IPs !       listed" >> $temp/ip_bl
else
  echo -e "\n! Rescure IPs        file missing" >> $temp/ip_bl
fi
if [ -f $temp/ip_bl ] && [[ $(grep -c '!' $temp/ip_bl) -gt 0 ]]; then
  cat $temp/ip_bl
else
  echo -e "\n+ IP Blocklists:      not listed"
fi
}

f_IP_REPUTATION(){
[[ $target_type = "dnsrec" ]] || echo -e "\nIP REPUTATION ($1)\n\n"
if [ $target_type = "default" ] || [ $target_type = "web" ]; then
  f_GREY_NOISE "$1"; f_ISC "$1"
fi
f_PROJECT_HONEYPOT "$1"; f_STOP_FSPAM "$1"; f_DNS_BLOCKLIST_CHECK "$1"; f_IP_BLOCKLIST_CHECK "$1"
}

f_IP_REPUTATION2(){
[[ $target_type = "dnsrec" ]] && echo -e "\n$1\n" || echo -e "\nIP REPUTATION ($1)\n"
f_BOGON "$1"
if [ $bogon = "TRUE" ] ; then
  f_BOGON_INFO "$1"
else
  f_PROJECT_HONEYPOT "$1" > $temp/ip_rep; f_STOP_FSPAM "$1" >> $temp/ip_rep
  f_DNS_BLOCKLIST_CHECK "$1" >> $temp/ip_rep; f_IP_BLOCKLIST_CHECK "$1" >> $temp/ip_rep
  [[ -f $temp/ip_rep ]] && sed '/^$/d' $temp/ip_rep && rm $temp/ip_rep; echo ''
fi
}

f_ISC(){
$CURL -s "https://isc.sans.edu/api/ip/$1?json" > $temp/iscip.json
if [ -f $temp/iscip.json ]; then
  ip_num=$($JQ '.ip.number' $temp/iscip.json); incidents=$($JQ '.ip.count?' $temp/iscip.json | sed '/null/d')
  if [ -n "$incidents" ]; then
    ip_attacks=$($JQ '.ip.attacks?' $temp/iscip.json); ip_mindate=$($JQ '.ip.mindate?' $temp/iscip.json)
    ip_maxdate=$($JQ '.ip.maxdate?' $temp/iscip.json)
    $CURL -s "https://isc.sans.edu/api/ipdetails/$1?json" > $temp/ipdetails.json
    target_ports=$(jq -r '.[] | .targetport?' $temp/ipdetails.json | sort -ug | tr '[:space:]' ' '; echo '')
    protocols=$(jq -r '.[] | .protocol?' $temp/ipdetails.json | sort -ug | sed 's/16/CHAOS/' | sed 's/17/UDP/' |
    sed 's/6/TCP/' | sed 's/1/ICMP/' | sed 's/2/IGMP/' | sed 's/5/ST/' | tr '[:space:]' ' '; echo '')
    [[ -n "$target_ports" ]] && echo ''
    echo -e "\n! SANS ISC !          incidents: $incidents | attacks: $ip_attacks  ($ip_mindate - $ip_maxdate)"
    [[ -n "$target_ports" ]] && echo -e "\n                      protocols: $protocols; target ports: $target_ports\n"
  else
    echo -e "\n+ SANS ISC:           No results for $ip_num"
  fi; rm $temp/iscip.json
fi
}

f_PROJECT_HONEYPOT(){
if [ -n "$api_key_honeypot" ]; then
  res=$($DIG +short ${api_key_honeypot}.$(echo $1 | awk -F'.' '{printf $4 "." $3 "." $2 "." $1}').dnsbl.httpbl.org)
  if [[ -n "$res" ]]; then
    ph_lseen=$(echo "$res" | awk -F'.' '{print $2}'); ph_score=$(echo "$res" | awk -F'.' '{print $3}')
    type=$(echo "$res" | awk -F'.' '{print $4}'); [[ $type = "0" ]] && agent_cat="search engine"
    [[ $type = "1" ]] && agent_cat="suspicious"; [[ $type = "2" ]] && agent_cat="harvester"
    [[ $type = "4" ]] && agent_cat="comment spammer"; [[ $type = "5" ]] && agent_cat="suspicious/comment spammer"
    [[ $type = "6" ]] && agent_cat="harvester/comment spammer"; [[ -z "$agent_cat" ]] && agent_cat="category: unknown"
    if [ $type = "0" ]; then
      if [ $score = "0" ]; then
        seng="undocumented"
      elif [ $score = "3" ]; then
        seng="Baidu"
      elif [ $score = "5" ]; then
        seng="Google"
      elif [ $score = "8" ]; then
        seng="Yahoo"
      else
        seng="Other"
      fi
        echo -e "\n+ Project Honeypot:   $agent_cat | agent: $seng | last: $ph_lseen day(s) ago"
    else
        echo -e "\n! Project Honeypot !  $agent_cat | threat score: $ph_score | last: $ph_lseen day(s) ago"
    fi
  else
    echo -e "\n+ Project Honeypot:   not listed"
  fi
else
  echo -e "\n! Project Honeypot:    API key required (see help)"
fi
}

f_STOP_FSPAM(){
$CURL -s "http://api.stopforumspam.org/api?ip=$1&json&badtorexit" > $temp/fs.json
if [ -f $temp/fs.json ] && [[ $($JQ '.success?' $temp/fs.json) = "1" ]]; then
  freq=$($JQ '.ip.frequency?' $temp/fs.json)
  fspam_geo=$($JQ '.ip.country?' $temp/fs.json | tr [:lower:] [:upper:])
  torexit=$($JQ '.ip.torexit?' $temp/fs.json | sed 's/1/TOR/' | sed '/null/d')
  if [[ $($JQ '.ip.appears?' $temp/fs.json) = "0" ]]; then
    echo -e "\n+ Stop Forum SPAM:    not listed; country: $fspam_geo $torexit"
  else
    appears=$($JQ '.ip.appears' $temp/fs.json | sed 's/1/Appeared/')
    last=$($JQ '.ip.lastseen' $temp/fs.json | cut -d ' ' -f 1)
    freq=$($JQ '.ip.frequency' $temp/fs.json); conf=$($JQ '.ip.confidence' $temp/fs.json)
    echo -e "\n! Stop Forum SPAM !   $appears $freq times; last: $last;  country: $fspam_geo  $torexit"
  fi
else
  echo -e "\n! Stop Forum SPAM:    no response"
fi
}

# -------------------------------------  TOR  -------------------------------------

f_TOR(){
is_tor=$($DIG +short -t a $(echo $1 | awk -F'.' '{printf $4 "." $3 "." $2 "." $1}').tor.dan.me.uk.)
[[ -n "$is_tor" ]] && echo "TOR: true" || echo "TOR: false"
}

f_RELAY_FLAGS(){
if [ -f $temp/tor_info ] && [[ $(grep -c 'N:' $temp/tor_info) -gt 0 ]]; then
  awk -F'/F:' '{print $2}' $temp/tor_info | grep -sEo "B|E|F|G|S|R|X|V" | sed 's/V/Valid/' | sed 's/E/Exit/' |
  sed 's/F/Fast/' | sed 's/G/Guard/' | sed 's/X/HiddenExit/' | sed 's/B/BadExit/' | sed 's/R/Running/' | sed 's/S/Stable/' | sort -u |
  sed 's/$/,/' | tr '[:space:]'  ' ' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/,$//'; echo ''
fi
}

f_TOR_NODE(){
if [ -f $temp/tor_info ] && [[ $(grep -c 'N:' $temp/tor_info) -gt 0 ]]; then
  sed 's/N://' $temp/tor_info | awk -F'/F:' '{print $1}' | sed 's/\/P:/(tcp\//' | sed 's/$/)/' | tr '[:space:]' ' ' |
  sed 's/ /  /g' | sed 's/(/ (/g'; echo ''
fi
}

# -------------------------------------  DOMAIN REPUTATION  -------------------------------------

f_DOMAIN_BLOCKLIST_CHECK(){
if [ -f ${file_date}.hagezi_domains.txt ]; then
  [[ $(grep -w -c "$1" ${file_date}.hagezi_domains.txt) -gt 0 ]] && echo -e "\n ! Listed in Hagezi Domain Blocklist !"
else
  echo -e "\n! File ${file_date}.hagezi_domains.txt not found"
fi
if [ -f ${file_date}.hagezi_dyndns.txt ]; then
  check_dyndns=$(echo "$1" | rev | cut -d '.' -f -2 | rev)
  [[ $(grep -w -c "$check_dyndns" ${file_date}.hagezi_dyndns.txt) -gt 0 ]] && echo -e "\n ! Dynamic DNS Domain !"
fi
if [ -f ${file_date}.openphish_hosts.txt ]; then
  [[ $(grep -w -c "$1" ${file_date}.openphish_hosts.txt) -gt 0 ]] && echo -e "\n ! Listed in OpenPhish Community Feed !"
else
  echo -e "\n! File ${file_date}.openphish.txt not found"
fi
if [ -f ${file_date}.android_campaign.txt ]; then
  [[ $(grep -w -c "$1" ${file_date}.android_campaign.txt) -gt 0 ]] &&  echo -e "\n ! Listed in Amnesty Tech 2023 Android Campaign Spyware Domain List !"
else
  echo -e "\n! File ${file_date}.android_campaign.txt not found"
fi  
if [ -f ${file_date}.cytrox.txt ]; then
  [[ $(grep -w -c "$1" ${file_date}.cytrox.txt) -gt 0 ]] &&  echo -e "\n ! Listed in Amnesty Tech Cytrox Spyware Domain List !"
else
  echo -e "\n! File ${file_date}.cytrox.txt not found"
fi
if [ -f ${file_date}.pegasus.txt ]; then
  [[ $(grep -w -c "$1" ${file_date}.pegasus.txt) -gt 0 ]] &&  echo -e "\n ! Listed in Amnesty Tech Pegasus Spyware Domain List !"
else
  echo -e "\n! File ${file_date}.pegasus.txt not found"
fi
if [ -f ${file_date}.phishing_army.txt ]; then
   [[ $(grep -w -c "$1" ${file_date}.phishing_army.txt) -gt 0 ]] && echo -e "\n ! Listed in Phishing Army Blocklist"
else
  echo -e "\n! File ${file_date}.phishing_army.txt not found"
fi
if [ -f ${file_date}.rescure_domains.txt ]; then
  [[ $(grep -w -c "$1" ${file_date}.rescure_domains.txt) -gt 0 ]] && echo -e "\n ! Listed in Rescure Domain Blocklist !"
else
  echo -e "\n! File ${file_date}.rescure_domains.txt not found"
fi
if [ -f ${file_date}.urlhaus_malware.txt ]; then
   [[ $(grep -w -c "$1" ${file_date}.urlhaus_malware.txt) -gt 0 ]] && echo -e "\n ! Listed in URLHaus Malware Domains !"
else
  echo -e "\n! File ${file_date}.urlhaus_malware.txt not found"
fi
if [ -f  ${file_date}.zonefiles.txt ]; then
   [[ $(grep -w -c "$1" ${file_date}.zonefiles.txt) -gt 0 ]] &&  echo -e "\n ! Listed in Zonefiles Blocklist !"
else
echo -e "\n File ${file_date}.zonefiles.txt not found"
fi
}

f_DOMAIN_REPUTATION(){
domain_bl_check=$(f_DOMAIN_BLOCKLIST_CHECK "$1")
echo -e "\n$1  DOMAIN/HOST REPUTATION\n"
if [ -n "$domain_bl_check" ]; then
  echo "$domain_bl_check"
else
  echo -e "Not listed (ok)"
fi
}

f_DOMAIN_THREAT_ENUM(){
host4=$(f_getHOST_A "$1"); [[ -n "$host4" ]] || host6=$(f_getHOST_AAAA "$1")
[[ -n "$host4" ]] && echo "$host4" | tee -a $temp/lookup1 >> $temp/lookup2
strip_host=$(echo "$1" | sed 's/^www.//' | sed 's/^mx.//')
strip_host=$(echo "$1" | sed 's/^www.//' | sed 's/^mx.//')
f_WHOIS_STATUS "$strip_host" > $temp/host_whois
if [[ $(grep -c "Domain:" $temp/host_whois) -eq 0 ]]; then
  remove_sub=$(echo "$1" | cut -d '.' -f 2-); try_hostname=$(f_EXTRACT_HOSTN "$remove_sub")
  [[ -n "$try_hostname" ]] && f_WHOIS_STATUS "$try_hostname" > $temp/host_whois
fi
[[ $(grep -c "Domain:" $temp/host_whois) -eq 0 ]] && domain_name=$(f_EXTRACT_HOSTN "$(grep -sE "^Domain" $temp/host_whois)")
if [[ -n "$domain_name" ]] && [[ "$domain_name" != "$1" ]]; then
  domain_host4=$(f_getHOST_A "$domain_name")
  [[ -n "$domain_host4" ]] || domain_host6=$(f_getHOST_AAAA "$domain_name")
fi
f_DOMAIN_REPUTATION "$1"; echo ''
[[ -n "$domain_name" ]] && [[ "$domain_name" != "$1" ]] && f_DOMAIN_REPUTATION "$domain_name"
if [ -z "$domain_name" ]; then
  if [ -n "$target4" ]; then
    echo -e "\n$1 DNS\n\n$target4\n"
    for i in $(f_EXTRACT_IP4 "$target4"); do f_HOST_SHORT "$i"; done
    f_Medium
    for i in $(f_EXTRACT_IP4 "$target4"); do f_IP_REPUTATION2 "$i"; done
   fi
else
   echo ''; f_Medium; cat $temp/host_whois; f_Medium
   echo -e "\nA\n"; [[ -n "$host4" ]] && echo -e "$1\t\t$host4" || echo -e "No A record found for $1"
  [[ -n "$host6" ]] && echo -e "\n\nAAAA\n\n$1\t\t$host6"
  if [ -n "$domain_host4" ]; then
      echo -e "\nA\n"; echo -e "$domain_name\t\t$domain_host4"
      f_EXTRACT_IP4 "$domain_host4" | tee -a $temp/lookup1 >> $temp/lookup2
  else
    [[ -n "$domain_host6" ]] && echo -e "\n\nAAAA\n\n$domain_name\t\t$domain_host6" || echo -e "$domain_name \n\nNo A or AAAA record found"
  fi
  f_GOOGLE_DNS "$domain_name"
  if [ -f $temp/lookup2 ]; then
    f_Medium; f_DNS_PREFIXES; f_Medium
    for a in $(f_EXTRACT_IP4 "$temp/lookup1"); do f_HOST_SHORT "$a"; done; f_Medium
    for a in $(f_EXTRACT_IP4 "$temp/lookup3"); do f_HOST_ABUSEC "$a"; done
    f_Medium; f_PREFIX "$temp/lookup2"
    for h in $(f_EXTRACT_IP4 "$temp/lookup1"); do f_IP_REPUTATION2 "$h"; done; echo ''
    for a in $(f_EXTRACT_IP4 "$temp/lookup3"); do f_IP_REPUTATION2 "$a"; done
  fi
  if [ -f $temp/detected_ports ] && [[ $(grep -sEoc "80|443" $temp/detected_ports) -gt 0 ]]; then
    f_URLSCAN_DUMP "$1" && cat $temp/uscan_results
  else
    f_URLSCAN_DUMP "$domain_name" && cat $temp/uscan_results
  fi
  f_CERT_SPOTTER "$domain_name"
fi
}

f_HOST_ABUSEC(){
$CURL -s -m 7 "http://ip-api.com/json/${1}?fields=16795137" > $temp/geo.json
abu=$($DIG +short $(f_REVERSE "$1").abuse-contacts.abusix.zone txt | tr -d '"' | grep '@' | sed 's/^[ \t]*//;s/[ \t]*$//')
org=$($JQ '.org' $temp/geo.json); [[ -n "$org" ]] || org=$($JQ '.isp' $temp/geo.json)
[[ -n "$abu" ]] && print_contact="$org, $abu" || print_contact="$org"
geo_country=$($JQ '.country' $temp/geo.json | sed 's/United States/US/' | sed 's/United Kingdom/UK/')
hosting=$($JQ '.hosting' $temp/geo.json | sed 's/true/HOSTING/' | sed '/false/d')
echo -e "\n$1 ($geo_country)  $print_contact $hosting"
}

f_DNS_PREFIXES(){
for p4 in $(sort -t . -k 1,1n -k 2,2n -k 3,3n -u $temp/dns4); do f_getPFX "$p4"; done > $temp/pfx4.list
cat $temp/pfx4.list > $temp/pfx46.list
cut -d '|' -f 2 $temp/pfx4.list | tr -d ' ' | sort -u | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n > $temp/pfx.list
if [ -f $temp/dns6 ]; then
  for p6 in $(sort -t ':' -k 3,3 -u $temp/dns6); do f_getPFX "$p6"; done > $temp/pfx6.list
  [[ -f $temp/pfx6.list ]] && cut -d '|' -f 2 $temp/pfx6.list | tr -d ' ' | sort -u >> $temp/pfx.list && cat $temp/pfx6.list >> $temp/pfx46.list
fi
prefixes=$(grep -s '/' $temp/pfx.list)
if [ -n "$prefixes" ]; then
  for p in $prefixes; do
    pfx_allocation=$(grep -sw -m 1 "$p" $temp/pfx46.list | cut -d '|' -f 3,4,5 | sed 's/^[ \t]*//;s/[\t]*$//' | tr [:lower:] [:upper:])
    pfx_asn=$(grep -sw -m 1 "$p" $temp/pfx46.list | cut -d '|' -f 1 | tr -d ' '); pfx_asname=$(f_getASNAME "$pfx_asn")
    pfx_roa=$($CURL -s -m 5 --location --request GET "https://stat.ripe.net/data/rpki-validation/data.json?resource=$pfx_asn&prefix=$p" |
    $JQ '.data.status')
    spamhaus_listed=$(grep -sw "$p" ${file_date}.ip_drop.txt)
    echo -e "\n*> $p  (ROA: $pfx_roa)"; echo -e "\n   $pfx_allocation | $pfx_asname\n"
    [[ -n "$spamhaus_listed" ]] && echo -e " ! Prefix listed in Spamhaus DON'T ROUTE OR PEER !\n"
  done
fi
}

# -------------------------------------  SSL  -------------------------------------

f_QUERY_PROTOCOLS(){
echo "$1" | grep -sE "^New,|Secure Renegotiation|Compression:" | sed -e '/./{H;$!d;}' -e 'x;/New, (NONE)/d' |
sed '/^$/d' | tr '[:space:]' ' ' | sed 's/New, /\n/' | sed 's/Cipher is//' | sed 's/Cipher is//' | tr ',' ':' |
sed 's/Secure/\n          Secure/' | sed 's/ IS/:/' | sed 's/Compression:/| Compression:/' ; echo ''
}

f_CERT_INFO(){
local s="$*"
# Clean up
self_signed=""; verify_ok=""; peer=""; print_ips1=""; print_ips2=""; target_ip=""
[[ -f $temp/ssl ]] && rm $temp/ssl; [[ -f $temp/x509 ]] && rm $temp/x509; [[ -f $temp/ocsp ]] && rm $temp/ocsp
[[ -f $temp/leaf.pem ]] && rm $temp/leaf.pem; [[ -f $temp/issuer.pem ]] && rm $temp/issuer.pem
[[ -f $temp/ssl_ips ]] && rm $temp/ssl_ips; [[ -f $temp/tls_support ]] && rm $temp/tls_support
# Resolve hostnames
if [ $target_cat = "hostname" ]; then
  f_RESOLVE_ALL "$s" | head -7 > $temp/ssl_ips
  if [ -f $temp/ssl_ips ]; then
    if [[ $(wc -l < $temp/ssl_ips) -le 3 ]]; then
      print_ips46=$(cat $temp/ssl_ips | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//'; echo '')
    else
      print_ips4=$(f_EXTRACT_IP4 "$temp/ssl_ips" | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//'; echo '')
      print_ips6=$(f_EXTRACT_IP6 "$temp/ssl_ips" | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//'; echo '')
    fi
  else
    res_local=$(f_LOCAL_DNS "$s"); [[ -n "$res_local" ]] && f_EXTRACT_IP_ALL "$res_local" > $temp/ssl_ips
  fi
else
  echo "$s" > $temp/ssl_ips
fi
target_ip=$(f_EXTRACT_IP_ALL "$temp/ssl_ips" | head -1)
# No starttls
if [ $option_starttls = "0" ]; then
  echo | $OPENSSL s_client -connect [$s]:$tls_port 2>$temp/brief "${ssl_array1[@]}" -brief >> $temp/brief
  if grep -oq "CONNECTION ESTABLISHED" $temp/brief; then
    echo | $OPENSSL s_client -connect [$s]:$tls_port 2>/dev/null -status -showcerts -verify 5 > $temp/ossl
    echo | timeout 10 $OPENSSL s_client -connect [$s]:$tls_port 2>/dev/null | $OPENSSL x509 -text > $temp/x509
    if [ $quiet_dump = "false" ]; then
      for i in $(cat $temp/ssl_ips); do
        verify_instance=""
        if [[ $(wc -l < $temp/ssl_ips) -gt 1 ]]; then
          echo | $OPENSSL s_client -connect [$i]:$tls_port "${ssl_array1[@]}" 2>$temp/verify_instance -brief >> $temp/verify_instance
          verify_instance=$(f_VALUE ":" "$(grep -sE '^Verification:' $temp/verify_instance)")
          echo "IP: $i  (verify: $verify_instance)"; rm $temp/verify_instance
        fi
          f_QUERY_PROTOCOLS "$(echo | $OPENSSL s_client -connect [$i]:$tls_port 2>/dev/null -tls1)"
          f_QUERY_PROTOCOLS "$(echo | $OPENSSL s_client -connect [$i]:$tls_port 2>/dev/null -tls1_1)"
          f_QUERY_PROTOCOLS "$(echo | $OPENSSL s_client -connect [$i]:$tls_port 2>/dev/null -tls1_2)" 
          f_QUERY_PROTOCOLS "$(echo | $OPENSSL s_client -connect [$i]:$tls_port 2>/dev/null -tls1_3 | grep 'New')"
      done > $temp/tls_support
    fi
  fi
else
  if [ -n "$target_ip" ]; then
    # SMTP
    if [ $option_starttls = "1" ]; then
      echo | $OPENSSL s_client -starttls smtp -connect [$target_ip]:25 2>$temp/brief "${ssl_array1[@]}" -brief >> $temp/brief
      if grep -oq "CONNECTION ESTABLISHED" $temp/brief; then
        stls_port=25; stls_pro=smtp
      elif grep -oq "wrong version number" $temp/brief; then
        echo | $OPENSSL s_client -starttls smtp -connect [$target_ip]:587 2>$temp/brief  "${ssl_array1[@]}" -brief >> $temp/brief
        if grep -oq "CONNECTION ESTABLISHED" $temp/brief; then
          stls_port=587; stls_pro=smtp
        fi
      fi
    # IMAP
    elif [ $option_starttls = "2" ]; then
      echo | $OPENSSL s_client -starttls imap -connect [$target_ip]:993 2>$temp/brief "${ssl_array1[@]}" -brief >> $temp/brief
      if grep -oq "CONNECTION ESTABLISHED" $temp/brief; then
        stls_port=994; stls_pro=imap
      elif grep -oq "wrong version number" $temp/brief; then
        echo | $OPENSSL s_client -starttls smtp -connect [$target_ip]:143 2>$temp/brief  "${ssl_array1[@]}" -brief >> $temp/brief
        if grep -oq "CONNECTION ESTABLISHED" $temp/brief; then
          stls_port=143; stls_pro=imap
        fi
      fi
    # POP3
    elif [ $option_starttls = "3" ]; then
      echo | $OPENSSL s_client -starttls pop3 -connect [$target_ip]:995 2>$temp/brief "${ssl_array1[@]}" -brief >> $temp/brief
      if grep -oq "CONNECTION ESTABLISHED" $temp/brief; then
        stls_port=995; stls_pro=smtp
      elif grep -oq "wrong version number" $temp/brief; then
        echo | $OPENSSL s_client -starttls pop3 -connect [$target_ip]:110 2>$temp/brief  "${ssl_array1[@]}" -brief >> $temp/brief
      if grep -oq "CONNECTION ESTABLISHED" $temp/brief; then
        stls_port=110; stls_pro=pop3
      fi
    fi
    # FTP
    elif [ $option_starttls = "4" ]; then
      echo | $OPENSSL s_client -starttls ftp -connect [$target_ip]:21 2>$temp/brief "${ssl_array1[@]}" -brief >> $temp/brief
      if grep -oq "CONNECTION ESTABLISHED" $temp/brief; then
        stls_port=21; stls_pro=ftp
      fi
    # LDAP
    elif [ $option_starttls = "5" ]; then
      echo | $OPENSSL s_client -starttls ldap -connect [$target_ip]:636 2>$temp/brief "${ssl_array1[@]}" -brief >> $temp/brief
      if grep -oq "CONNECTION ESTABLISHED" $temp/brief; then
        stls_port=636; stls_pro=ldap
      elif grep -oq "wrong version number" $temp/brief; then
        echo | $OPENSSL s_client -starttls ldap -connect [$target_ip]:389 2>$temp/brief  "${ssl_array1[@]}" -brief >> $temp/brief
        if grep -oq "CONNECTION ESTABLISHED" $temp/brief; then
          stls_port=389; stls_pro=ldap
        fi
      fi
    fi
    if [ -n "$stls_port" ]; then
      echo | $OPENSSL s_client -starttls $stls_pro -connect [$target_ip]:$stls_port "${ssl_array2[@]}" 2>/dev/null -status -showcerts -verify 5 > $temp/ossl
      echo | $OPENSSL s_client -starttls $stls_pro -connect [$target_ip]:$stls_port "${ssl_array2[@]}" 2>/dev/null | $OPENSSL x509 -text > $temp/x509
      if [ $quiet_dump = "false" ]; then
        for i in $(cat $temp/ssl_ips); do
          verify_instance=""
          if [[ $(wc -l < $temp/ssl_ips) -gt 1 ]]; then
            echo | $OPENSSL s_client -starttls $stls_pro -connect [$i]:$stls_port "${ssl_array1[@]}"  2>$temp/verify_instance -brief >> $temp/verify_instance
            verify_instance=$(f_VALUE ":" "$(grep -sE '^Verification:' $temp/verify_instance)")
            echo "IP: $i  (verify: $verify_instance)"; rm $temp/verify_instance
          fi
          f_QUERY_PROTOCOLS "$(echo | $OPENSSL s_client -starttls $stls_pro -connect [$i]:$stls_port 2>/dev/null -tls1)"
          f_QUERY_PROTOCOLS "$(echo | $OPENSSL s_client -starttls $stls_pro -connect [$i]:$stls_port 2>/dev/null -tls1_1)"
          f_QUERY_PROTOCOLS "$(echo | $OPENSSL s_client -starttls $stls_pro -connect [$i]:$stls_port 2>/dev/null -tls1_2)"
          f_QUERY_PROTOCOLS "$(echo | $OPENSSL s_client -starttls $stls_pro -connect [$i]:$stls_port 2>/dev/null -tls1_3 | grep 'New')"
        done > $temp/tls_support
      fi
    fi
  fi
fi
# Subject cert
[[ -f $temp/x509 ]] && $OPENSSL x509 -in $temp/x509 -outform PEM -out $temp/leaf.pem
if [ -f $temp/leaf.pem ]; then
  # Verification
  verify=$(f_VALUE ":" "$(grep -sE '^Verification:' $temp/brief)")
  verify_ok=$(echo "$verify" | grep -m 1 -so 'OK'); verify_error=$(grep -m1 'error' $temp/brief) 
  self_signed=$(grep -m 1 -so 'self-signed certificate' $temp/brief)
  start_date=$(f_getX509 "startdate" | awk -F'=' '{print $NF}' | awk '{print $1,$2,$4}')
  end_date=$(f_getX509 "enddate" | awk -F'=' '{print $NF}' | awk '{print $1,$2,$4}')
  cert_sha256=$(f_getFINGERPRINT "$temp/leaf.pem"); serial=$(f_getX509 "serial" | awk -F'=' '{print $NF}')
  peer=$(f_VALUE ":" "$(grep -sE '^Verified peername:' $temp/brief)"); [[ -n "$peer" ]] && print_peer="($peer)"
  if [ -n "$verify_ok" ] && [ -z "$self_signed" ]; then
    f_EXTRACT_CERT "$(sed -n '/1 s:/,/-----END CERTIFICATE-----/p' $temp/ossl)" > $temp/2
    $OPENSSL x509 -in $temp/2 -outform PEM -out $temp/2.pem
    diff_1_2=$(diff -q <($OPENSSL x509 -in $temp/leaf.pem -noout -issuer_hash) <($OPENSSL x509 -in $temp/2.pem -noout -subject_hash))
    [[ -n "$diff_1_2" ]] || mv $temp/2.pem $temp/issuer.pem
    # OCSP
    num_certs=$(grep -c 'BEGIN CERTIFICATE' $temp/ossl)
    if [[ "$num_certs" -gt 1 ]]; then
      stapling_false=$(grep -s 'OCSP response: no response' $temp/ossl)
      response_status=$(grep 'OCSP Response Status:' $temp/ossl | cut -d ':' -f 2- | cut -d '(' -f 1 | tr -d ' ')
      if [ -n "$response_status" ]; then
        stapling="true"
        if [[ $response_status = "successful" ]]; then
          cert_status=$(f_VALUE ":" "$(grep -A 12 'OCSP Response Status:' $temp/ossl | grep 'Cert Status:')")
        else
          cert_status="$response_status"
        fi
      fi
      if [ -n "$stapling_false" ]; then
        stapling="false"; ocsp_uri=$(f_getX509 "ocsp_uri")
        if [ -f $temp/issuer.pem ]; then
          $TOUT 15 $OPENSSL ocsp -issuer $temp/issuer.pem -cert $temp/leaf.pem -url "$ocsp_uri" 2>/dev/null > $temp/ocsp
        fi
        if [ -f $temp/ocsp ]; then
          cert_status=$(f_VALUE ":" "$(grep -E "leaf.pem:" $temp/ocsp)")
          [[ -n "$cert_status" ]] && ocsp_resp="$(f_toUPPER "$cert_status") (stapling: $stapling)" || ocsp_resp="Error retrieving data"
        fi
      elif  [ -n "$stapling_true" ]; then
        ocsp_resp="$stapling_true"
      else
        ocsp_resp="Error retrieving data"
      fi
    fi
  fi
  # Algos
  proto=$(f_VALUE ":" "$(grep -E '^Protocol version:' $temp/brief)")
  cipher=$(f_VALUE ":" "$(grep -E '^Ciphersuite:' $temp/brief)")
  tmp_key=$(f_VALUE ":" "$(grep -E '^Server Temp Key:' $temp/brief)")
  sign=$(f_VALUE ":" "$(grep -sE '^Signature type:' $temp/brief)")
  sign_hash=$(f_VALUE ":" "$(grep -sE '^Hash used:' $temp/brief)")
  pubkey=$(f_VALUE ":" "$(grep -E "Public Key Algorithm:|Public-Key:|NIST CURVE:" $temp/x509)" | tr '[:space:]' ' '; echo '')
  # Subject
  f_getX509 "subject" > $temp/sub
  s_cn=$(f_VALUE "=" "$(grep commonName $temp/sub)"); s_org=$(f_VALUE "=" "$(grep organizationName $temp/sub)")
  s_cc=$(f_VALUE "=" "$(grep countryName $temp/sub)"); s_mail=$(f_getX509 "email" | grep -sEo "$REGEX_MAIL")
  # Issuer
  f_getX509 "issuer" > $temp/ca; ca_org=$(f_VALUE "=" "$(grep organizationName $temp/ca)")
  ca_cn=$(f_VALUE "=" "$(grep commonName $temp/ca)"); ca_cc=$(f_VALUE "=" "$(grep countryName $temp/ca)")
  [[ $option_starttls = "0" ]] && print_proto="http" || print_proto="$stls_pro"
  if [ -z "$self_signed" ]; then
    # DNS CAA
    if [ $target_type = "ssl_target" ] || [ $target_type = "web" ]; then
      [[ $target_cat = "hostname" ]] && dns_caa=$($DIG +short caa $s | grep -sEi "issue|issuewild")
    fi
    # Root CA
    if [ -n $temp/issuer.pem ]; then
      if [[ $num_certs -le 3 ]]; then
        $OPENSSL x509 -in $temp/issuer.pem -noout -nameopt multiline -issuer > $temp/root
      else
        f_EXTRACT_CERT "$(sed -n '/2 s:/,/-----END CERTIFICATE-----/p' $temp/ossl)" > $temp/3
        $OPENSSL x509 -in $temp/3 -outform PEM -out $temp/root.pem
        $OPENSSL x509 -in $temp/issuer.pem -noout -nameopt multiline -issuer > $temp/root
      fi
      root_cn=$(f_VALUE "=" "$(grep commonName $temp/root)")
      root_org=$(f_VALUE "=" "$(grep organizationName $temp/sub)")
      root_cc=$(f_VALUE "=" "$(grep countryName $temp/ca)"); [[ -n "$root_cc" ]] && print_cc="($root_cc)"
    fi
  fi
  # Selected ciphers per proto / secure renegotiation
  if [ $quiet_dump = "false" ]; then
    if grep -q 'TLS' $temp/tls_support; then
      if [[ $(wc -l < $temp/ssl_ips) -eq 1 ]]; then
        supported=$(sed '/^$/d' $temp/tls_support | sed '/TLS/{x;p;x}')
      else
        supported=$(sed '/^$/d' $temp/tls_support | sed 's/IP: /\n\n/' | sed '/TLS/{x;p;x}')
      fi
      tls_support=$(grep -sEo "SSLv3|TLSv1(\.[0-3])?" $temp/tls_support | sort -uV |  tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//' |
      sed 's/ /  /g'; echo '')
    fi
  fi
  [[ $option_starttls = "0" ]] && print_proto="http" || print_proto="$stls_pro"
  # -----------  PRINT SSL INFO  -----------
  f_HEADLINE3 "[SSL]   $s   ($print_proto)   $file_date" >> $temp/ssl
  if [ -n "$s_org" ] ; then
    echo -e "\nSubject:        $s_cn  ($s_org, $s_cc)  $s_mail" >> $temp/ssl
  else
    echo -e "\nSubject:        $s_cn  $s_cc $s_mail" >> $temp/ssl
  fi
  [[ -n "$print_ips46" ]] && echo -e "\nDNS:            $print_ips46\n" >> $temp/ssl
  if [ -n "$print_ips4" ] || [ -n "$print_ips6" ]; then
    [[ -n "$print_ips4" ]] && echo -e "\nDNS:            $print_ips4" >> $temp/ssl
    [[ -n "$print_ips6" ]] && echo -e "\nDNS:            $print_ips6" >> $temp/ssl
    echo '' >> $temp/ssl
  fi
  if [ -n "$verify_ok" ]; then
    if [ -n "$self_signed" ]; then
     echo -e "\nVerify:         $self_signed" >> $temp/ssl
    else
      echo -e "\nVerify:         $verify  $print_peer" >> $temp/ssl
    fi
  else
    echo -e "\nVerify:         $verify_error" >> $temp/ssl
  fi
  [[ -n "$ocsp_resp" ]] && [[ -z "$$print_ips1" ]] && echo '' >> $temp/ssl
  echo -e "\nValid:          $start_date  ->  $end_date" >> $temp/ssl
  [[ -n "$ocsp_resp" ]] && echo -e "\nOCSP:           $ocsp_resp" >> $temp/ssl
  [[ -n "$root_cn" ]] && echo '' >> $temp/ssl
  echo -e "\nIssuer:         $ca_cn  ($ca_org, $ca_cc)" >> $temp/ssl
  [[ -n "$root_cn" ]] && echo -e "\nRoot:           $root_cn $root_org $print_cc" >> $temp/ssl
  if [ $target_type = "ssl_target" ] || [ $target_type = "web" ]; then
    [[ -n "$self_signed" ]] && [[ -z "$dns_caa" ]] && [[ $target_cat = "hostname" ]] && echo -e "\nDNS CAA:        no CAA record" >> $temp/ssl
  fi
  echo '' >> $temp/ssl; f_Long >> $temp/ssl
  echo -e "Serial:         $serial" >> $temp/ssl
  echo -e "\nCert SHA256     $cert_sha256" >> $temp/ssl; f_Long >> $temp/ssl
  if [ -n "$tls_support" ]; then
    echo -e "\nProtocols:      $tls_support" >> $temp/ssl
    echo -e "\nCipher used:    $proto  |  $cipher  |  $tmp_key" >> $temp/ssl
  else
    echo -e "\nCipher:         $proto  |  $cipher  |  $tmp_key" >> $temp/ssl
  fi
  echo -e "\nPubKey:         $pubkey" >> $temp/ssl
  echo -e "\nSignature:      $sign with $sign_hash\n" >> $temp/ssl
  # Print ciphers per proto
  if [ $quiet_dump = "false" ] && [ -n "$supported" ]; then
    if [[ $(f_countW "$tls_support") -gt 1 ]] || [[ $(wc -w < $temp/ssl_ips) -gt 1 ]]; then
      f_Medium >> $temp/ssl; echo -e "Negotiated ciphers per protocol:" >> $temp/ssl
      echo -e "$supported\n" >> $temp/ssl
    fi
  fi
  # SANs
  alt_names=$(f_getSANS | tr '[:space:]' ' ' | fmt -s -w 70; echo '')
  if [ -n "$alt_names" ]; then
    f_Medium >> $temp/ssl; echo -e "SUBJECT ALT. NAMES\n\n$alt_names\n" >> $temp/ssl
  fi
  # Compare SHAs for multiple IP addresses
  if [ $quiet_dump = "false" ] && [ $target_type != "web" ] && [ $target_type != "dnsrec" ]; then
    if [[ $(f_countW "$(cat $temp/ssl_ips)") -gt 1 ]]; then
      f_Long >> $temp/ssl; echo -e "CERTIFICATE SHA 256\n" >> $temp/ssl
      for i in $(cat $temp/ssl_ips); do
        if [ $option_starttls = "0" ]; then
          echo | timeout 3 $OPENSSL s_client -connect [$i]:$tls_port -servername $s 2>/dev/null |
          $OPENSSL x509 -noout -nocert -nameopt multiline -subject -issuer -fingerprint -sha256 |
          sed '/subject=/{x;p;x;}' | sed '/issuer=/{x;p;x;}' > $temp/sha256
        else
          echo | timeout 3 $OPENSSL s_client -starttls $stls_pro -connect [$i]:$stls_port -servername $s 2>/dev/null |
          $OPENSSL x509 -noout -nocert -nameopt multiline -subject -issuer -fingerprint -sha256 |
          sed '/subject=/{x;p;x;}' | sed '/issuer=/{x;p;x;}' > $temp/sha256
        fi
        coname=$(sed -e '/./{H;$!d;}' -e 'x;/subject=/!d'  $temp/sha256 | grep -i 'commonName' | cut -d '=' -f 2- | sed 's/^ *//')
        issuer_org=$(sed -e '/./{H;$!d;}' -e 'x;/issuer=/!d'  $temp/sha256 | grep -i 'organizationName' | cut -d '=' -f 2- | sed 's/^ *//')
        cert_sha=$(grep -i 'SHA256 Fingerprint=' $temp/sha256 | cut -s -d '=' -f 2- | sed 's/://g' | tr [:upper:] [:lower:] | sed 's/^ *//')
        echo "$i | $coname | CA: $issuer_org | $cert_sha"
      done > $temp/sha256_compare
      sha_diff=$(sort -t '|' -k 2 -u $temp/sha256_compare)
      if [[ $(f_countL "$sha_diff" ) -gt 1 ]]; then
        echo '' >> $temp/ssl; sed '/|/G' $temp/sha256_compare >> $temp/ssl
      else
        print_cert_sha=$(cut -d '|' -f 4 $temp/sha256_compare | tr -d ' ' | sort -u)
        echo -e "$print_cert_sha\n\nMATCHED BY HOSTS:\n" >> $temp/ssl
        f_printADDR "$temp/ssl_ips" | sed G >> $temp/ssl
      fi
    fi
  fi
  #  DNS CAA (ssl_target or web)
  if [ -n "$dns_caa" ]; then
    f_Medium >> $temp/ssl; echo -e "DNS CAA ($s)\n\n$dns_caa\n" >> $temp/ssl
  fi
  [[ $quiet_dump = "false" ]] && cat $temp/ssl
  if [ $ssl_diag = "true" ]; then
    [[ $option_starttls = "0" ]] && target_port="$tls_port" || target_port="$stls_port"
    $NMAP $s -sT -Pn -p $target_port -R --resolve-all --open -script=http-date,http-server-header,ssl-date,sslv2,ssl-heartbleed,ssl-dh-params,ssl-enum-ciphers,tls-nextprotoneg 2>/dev/null |
    tr -d '|' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/^_ //' > $temp/nmap_ssl
  fi
  [[ -f $temp/nmap_ssl ]] && f_printNMAP_SSL | tee -a $temp/ssl
  cat $temp/ssl > $temp/print_cert
  # Cert to file
  f_printCERT >> $temp/print_cert
  [[ $option_starttls = "0" ]] && f_printCERT > ${outdir}/CERT.http_${s}_${file_date}.txt
  [[ $option_starttls = "1" ]] && f_printCERT > ${outdir}/CERT.smtp_${s}_${file_date}.txt
  [[ $option_starttls = "2" ]] && f_printCERT > ${outdir}/CERT.imap_${s}_${file_date}.txt
  [[ $option_starttls = "3" ]] && f_printCERT > ${outdir}/CERT.pop3_${s}_${file_date}.txt
  [[ $option_starttls = "4" ]] && f_printCERT > ${outdir}/CERT.ftp_${s}_${file_date}.txt
  [[ $option_starttls = "4" ]] && f_printCERT > ${outdir}/CERT.ldap_${s}_${file_date}.txt
fi
}

f_CERT_SPOTTER(){
dnsnames=""
if [ $include_subs = "true" ]; then
  $CURL -s -m 15 "https://api.certspotter.com/v1/issuances?domain=${1}&include_subs=true&expand=dns_names&expand=issuer&expand=cert" > $temp/certs.json
  [[ -f $temp/certs.json ]] && echo '' && f_HEADLINE3 " [DOMAIN CERTIFICATES]  $1  [certspotter.com]  $file_date"
else
  $CURL -s -m 15 "https://api.certspotter.com/v1/issuances?domain=${1}&expand=dns_names&expand=issuer&expand=cert" > $temp/certs.json
  [[ -f $temp/certs.json ]] &&  f_HEADLINE2 "$1  SSL  [certspotter.com]\n"
fi
if [ -f $temp/certs.json ]; then
  dnsnames=$($JQ '.[].dns_names | .[]' $temp/certs.json)
  if [ -n "$dnsnames" ]; then
    issuances=$($JQ '.[] | {Subject: .dns_names[], Issuer: .issuer.name, Issued: .not_before, Expires: .not_after, Revoked: .revoked, CertSHA256: .cert.sha256}' $temp/certs.json |
    tr -d '}"{,' | sed 's/^ *//' | sed '/^$/d' | sed 's/C=/\nC: /g' | sed 's/ST=/\nST=/g' | sed 's/L=/\nL=/g' |
    sed 's/OU=/\nOU=/g' | sed 's/O=/\nO: /g' | sed 's/CN=/\nCN: /g' | sed 's/^ *//' | sed 's/^ *//' |
    sed '/^ST=/d' | sed '/^OU=/d' | sed '/^L=/d' | tr '[:space:]' ' ' | sed 's/Subject:/\nSubject:/g' |
    sed 's/ O:/| O:/g' | sed 's/ CN:/| CN:/g' | sed 's/^ *//')
    crt_shas=$($JQ '.[] | {Subject: .dns_names[], Issuer: .issuer.name, Issued: .not_before, Expires: .not_after, Revoked: .revoked, CertSHA256: .cert.sha256}' $temp/certs.json | tr -d '{",}' | sed 's/^ *//' | sed '/^$/d' | tr '[:space:]' ' ' | sed 's/Subject:/\nSubject:/g' | awk '{print $NF}' | sort -u)
    for c in $crt_shas; do
      echo -e "\n$c (CertSha-256)"
      echo "$issuances" | grep -w "${c}" | awk -F'CertSHA256:' '{print $1}' | sed 's/Subject:/\n\nSubject:/g' | sed 's/Issuer:/\nIssuer:/g' |
      sed 's/Issued:/\nIssued: /g' | sed 's/Expires:/\nExpires:/g' | sed 's/Revoked:/\nRevoked:/'
    done
    echo "$dnsnames" | sed 's/^\*\.//' | sed '/sni.cloudflaressl.com/d' | sort -u >> $temp/dnsnames
  else
    echo -e "\nNo results\n"
  fi
else
  echo -e "\nNo response\n"
fi
}

f_getFINGERPRINT(){
local cert_input="$*"
$OPENSSL x509 -noout -in $cert_input -fingerprint -sha256 | awk -F'=' '{print $NF}' | tr -d ':'
}

f_getSANS(){
sed -n '/Subject Alternative Name:/,/BEGIN CERTIFICATE/p' $temp/x509 | sed 's/DNS:/\nDNS:/g' | sed 's/IP:/\nIP:/g' |
grep -E "DNS:|IP:" | sed 's/DNS://g' | sed 's/IP://g' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d'
}

f_getX509(){
local flag="-$*"
$OPENSSL x509 -noout -nameopt multiline -in $temp/leaf.pem $flag
}

f_printCERT(){
f_HEADLINE3 " [SSL CERTIFICATE]  $1  ($file_date)"
echo ''; grep -E "Certificate chain|CN =|Server certificate"  $temp/ossl |
sed '/Certificate chain/{x;p;x;G}' | sed '/Server certificate/{x;p;x;G}'
f_Long2; f_EXTRACT_CERT "$(cat $temp/ossl)"
}

f_SSL_SHORT(){
if [ -f $temp/leaf.pem ]; then
  if ! [ -f $temp/ssl_ips ]; then
    wf_RESOLVE_ALL "$1" | head -12 > $temp/ssl_ips
  fi
  tlsv=$(f_VALUE ":" "$(grep -E '^Protocol version:' $temp/brief)")
  verify=$(f_VALUE ":" "$(grep -sE '^Verification:' $temp/brief)")
  end_date=$(f_getX509 "enddate" | awk -F'=' '{print $NF}' | awk '{print $1,$2,$4}')
  cert_sha256=$(f_getFINGERPRINT "$temp/leaf.pem")
  f_getX509 "subject" > $temp/sub; f_getX509 "issuer" > $temp/ca
  s_cn=$(f_VALUE "=" "$(grep commonName $temp/sub)")
  ca_org=$(f_VALUE "=" "$(grep organizationName $temp/ca)")
  ca_country=$(f_VALUE "=" "$(grep countryName $temp/ca)")
  peer=$(f_VALUE ":" "$(grep -sE '^Verified peername:' $temp/brief)")
  if [ -n "$peer" ]; then
    echo -e "\n + $1 - CN: $s_cn  (${tlsv}):\n"
    echo -e "   Peername: $peer  |  CA: $ca_org  |  $verify -> $end_date\n\n   $cert_sha256  (Cert SHA256)\n"
  else
    echo -e "\n  $1  (${tlsv}):\n"
    echo -e "   CN: $s_cn  |  CA: $ca_org  |  $verify -> $end_date\n\n   $cert_sha256  (Cert SHA256)\n"
  fi
  if [ $domain_enum = "true" ]; then
    sans=$(f_getSANS); [[ -n "$sans" ]] && echo -e "\nSANs:\n$sans\n"
  fi
  if [[ $(wc -w < $temp/ssl_ips) -gt 1 ]]; then
    for i in $(cat $temp/ssl_ips); do
      echo | timeout 3 $OPENSSL s_client -starttls $stls_pro -connect [$i]:$stls_port -servername $m 2>/dev/null |
      $OPENSSL x509 -nocert -nameopt multiline -subject -fingerprint -sha256 | sed '/subject=/{x;p;x;}' > $temp/sha256
      c_name=$(sed -e '/./{H;$!d;}' -e 'x;/subject=/!d'  $temp/sha256 | grep -i 'commonName' | cut -d '=' -f 2- | sed 's/^ *//')
      echo "$i | $c_name | $cert_sha"
    done > $temp/sha256_compare
    sha_diff=$(sort -t '|' -k 3 -u $temp/sha256_compare)
    if [[ $(f_countL "$sha_diff" ) -gt 1 ]]; then
      echo -e "\n  DIFFERENT SHA256 FINGERPRINTS FOUND FOR HOST CERTIFICATES:\n"
      sed '/|/G' $temp/sha256_compare
    fi
  fi
  rm $temp/leaf.pem; [[ -f $temp/ssl_ips ]] && rm $temp/ssl_ips
fi
}

#-------------------------------  NETWORKS -------------------------------

#**********************  BASIC FUNCTIONS & NETWORK WHOIS  ***********************

f_NET_DETAILS(){
[[ -f $temp/maxmind_data ]] && rm $temp/maxmind_data
[[ $net_report3 = "1" ]] || [[ $net_report3 = "3" ]] && f_NET_RDNS "$1"
[[  $net_report3 = "2" ]] || [[  $net_report3 = "3" ]] && echo '' && f_REV_IP "$1"
[[  $net_report4 = "1" ]] || [[  $net_report4 = "3" ]] && echo '' && f_BANNERS "$1"
[[  $net_report4 = "2" ]] || [[  $net_report4 = "3" ]] && echo '' && f_NET_CVEs "$1"
[[ $psweep = "true" ]] && f_PING_SWEEP "$1"
f_ROUTE_CONS "$1"
if [ $net_report2 = "1" ] || [ $net_report2 = "3" ]; then
  f_RELATED "$prefix"; f_NETGEO_MAXMIND "$1"; f_SUBNETS "$1"
fi
}

f_NET_HEADER(){
f_HEADLINE3 "[NET]  $1  $nh  ($file_date)"; echo ''
if [ $bogon = "TRUE" ]; then
  f_BOGON_INFO "$1"; f_Long
else
  f_getRIR "$1"; f_get_RIPESTAT_WHOIS "$1"
  if [ -f $temp/whois.json ]; then
    netaddr=$(f_getNET_RANGE "$1")
    if [ $rir != "lacnic" ]; then
      if [ $rir = "arin" ]; then
        netname=$($JQ '.data.records[]? | .[] | select (.key=="NetName") | .value' $temp/whois.json | tail -1)
        netpoc=$($JQ '.data.records[0]? | .[] | select (.key=="organization") | .value' $temp/whois.json | grep -v 'ARIN' | head -1)
      else
        netname=$($JQ '.data.records[0]? | .[] | select (.key=="netname") | .value' $temp/whois.json)
        netcc=$($JQ '.data.records[0]? | .[] | select (.key=="country") | .value' $temp/whois.json | head -1)
        netpoc=$($JQ '.data.records[0]? | .[] | select (.key=="org") | .value' $temp/whois.json | head -1)
        [[ -n "$netpoc" ]] || netpoc=$($JQ '.data.records[0]? | .[] | select (.key=="admin-c") | .value' $temp/whois.json | head -1)
      fi
      [[ -n "$netname" ]] && print_netname="$netname"
    fi
    if [ -n "$netcc" ]; then
      echo -e "\n$netaddr | $print_netname | $netcc | $(f_toUPPER "$rir") | $netpoc\n"
    else
      echo -e "\n$netaddr | $print_netname | $(f_toUPPER "$rir") | $netpoc\n"
    fi
    [[ -f $temp/irr_records ]] && echo -e "\nROUTE\n" && cat $temp/irr_records
    [[ $netop = "1" ]] && f_NET_DETAILS "$1"
  fi
fi
}

f_NET_INFO(){
net_name=$(f_getNETNAME); net_handle=$(f_VALUE ":" "$(grep -sEa -m 1 "^NetHandle:" $temp/whois)")
net_range=$(f_VALUE ":" "$(grep -sEa -m 1 "inet[6]?num|NetRange:|^in:|^i6:" $temp/whois)")
net_status=$(f_VALUE ":" "$(grep -sEa -m 1 "^status:|^NetType:" $temp/whois)")
created=$(f_VALUE ":" "$(grep -sEa -m 1 "^RegDate:|^created:" $temp/whois)" | cut -s -d '-' -f -2)
if [ $rir != "arin" ]; then
  org_id=$(f_VALUE ":" "$(grep -sEa -m 1 "^organisation:|^org:" $temp/whois)")
  [[ -n "$org_id" ]] && whois -h whois.$rir.net -- "--no-personal $org_id" > $temp/org && print_org=$(f_ORG_SHORT "$temp/org")
fi
#organisation=$(f_VALUE ":" "$(grep -sEa -m 1 "^Organization:" $temp/whois)")
descr=$(f_VALUE ":" "$(grep -sEa -m 1 "^descr:" $temp/whois)"); rir_caps=$(f_toUPPER "$rir") 
mnt_by=$(f_VALUE ":" "$(grep -sEa "^mnt-by:" $temp/whois)" | grep -E -v "RIPE-NCC-HM-MNT|RIPE-NCC-LEGACY-MNT" | head -1)
if [ $target_cat = "net4" ] && [ $rir = "ripe" ]; then
  space_usage_res=$($JQ '.data.resource?' $temp/su.json | sed '/null/d')
  if [ -n "$space_usage_res" ] && [[ $space_usage_res =~ "/" ]]; then
    net4_status=$(echo $net_status | grep -sEow "SUB-ALLOCATED PA|ASSIGNED PA" | cut -d ' ' -f 1)
    [[ -n "$net4_status" ]] && parent_net=$($JQ '.data.allocations[0] | .allocation'  $temp/su.json)
    if [ -n "$parent_net" ]; then
      parent=$($JQ '.data.allocations[] | {N: .allocation, A: .asn_name, S: .status}?' $temp/su.json | tr -d ']},"{[' |
      sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' | sed 's/^ *//' | sed 's/N: /\n/g' | sed 's/A: /(/' | sed 's/S:/)/' |
      sed 's/ )/)/' | sed '/)/G' | grep ')' | grep -w "$parent_net" | sed 's/)/) /'; echo '')
      if [ -z "$org_id" ]; then
        $TOUT 10 $WHOIS -h whois.$rir.net -- "--no-personal $parent_net" > $temp/parent_whois
        parent_org=$(f_ORG_SHORT "$temp/parent_whois")
      fi
    fi
  fi
elif [ $rir = "arin" ]; then
  get_parent_org=$($JQ '.data.records[]? | .[] | select (.key=="Organization") | .value' $temp/whois.json | tail -2 | head -1 | grep -v 'ARIN')
  if [ -n "$get_parent_org" ]; then
    get_parent_name=$($JQ '.data.records[]? | .[] | select (.key=="NetName") | .value' $temp/whois.json | tail -2 | head -1)
    get_parent_net=$($JQ '.data.records[]? | .[] | select (.key=="NetRange") | .value' $temp/whois.json | tail -2 | head -1)
    parent="$get_parent_net   ($get_parent_name)"; parent_org="$get_parent_org"
  fi
fi
get_netaddr=$(f_getNET_RANGE "$1")
if [ -n "$get_netaddr" ]; then
  [[ $get_netaddr =~ "/" ]] && net_addr="$get_netaddr"
fi
[[ -n "$net_addr" ]] && geo_query=$(echo "$net_addr" | awk '{print $1}') || geo_query=$(echo "$net_range" | awk '{print $1}')
[[ -n "$net_name" ]] && echo "$net_name" > $temp/netn; net_geo=$(f_NETGEO "$geo_query")
[[ -n "$net_addr" ]] && echo -e "\nNet:          $net_addr  ($net_name)" || echo -e "\nNet:          $net_name"
echo -e "\nRange:        $net_range  $print_handle\n"
if [ $rir = "arin" ]; then
  [[ -n "$is_arin" ]] && print_arin_alloc="|  Parent: $parent_name"
  echo -e "\nStatus        $net_status  |  $rir_caps, $created  |  $net_handle  $print_arin_alloc"
else
  echo -e "\nStatus        $net_status  |  $rir_caps, $created  | $mnt_by"
  [[ -n "$print_org" ]] || [[ -n "$descr" ]] || [[ -n "$parent" ]] && echo ''
fi
[[ -n "$net_geo" ]] && echo -e "\nCountry:      $net_geo"
[[ -n "$descr" ]] && echo -e "\nDescr:        $descr"
[[ -n "$descr" ]] && [[ -n "$parent_org" ]] && echo ''
[[ -n "$print_org" ]] && echo -e "\nOrg:          $print_org"
[[ -n "$parent" ]] && echo -e "\nParent:       $parent"
[[ -n "$parent_org" ]] && echo -e "\nParent Org:   $parent_org"
[[ $target_type != "nethandle" ]] && echo '' && f_ROUTE
if [ $rir = "arin" ]; then
  if [[ $(grep -oc '^OrgId:' $temp/whois) -gt 1 ]]; then
    for o in $($JQ '.data.records[]? | .[] | select (.key=="OrgId") | .value' $temp/whois.json | grep -wv 'ARIN' | sort -u); do
      echo ''; $WHOIS -h whois.arin.net o $od > $temp/org && f_ORG "$temp/org"
    done
  else
    f_POC "$temp/whois"
  fi
else
  if [ $option_detail = "2" ]; then
    f_POC "$temp/whois"
  else
    ac=$(grep -E "^admin-c:" $temp/whois | cut -d ':' -f 2- | sed 's/^ *//' | head -1)
    [[ -n "$ac" ]] && echo '' && f_Long && f_ADMIN_C "$ac"
  fi
  f_getRIR_OBJECTS "$temp/whois"
fi
if [ $net_report = "true" ] && [ $rir = "arin" ]; then
  if [ $net_report2 = "2" ] || [ $net_report2 = "3" ]; then
    timeout 20 $WHOIS -h whois.arin.net -- "n - . $net_name" | sed '/#/d' | grep -E '\(NET' |
    grep -v 'American Registry for Internet Numbers' > $temp/nets
  fi
fi
}

f_NET_SHORT(){
if [ $rir = "lacnic" ] && [ $option_detail != "0" ]; then
  f_LACNIC_WHOIS "$temp/whois"
else
  if [ -f $temp/whois.json ]; then
    netaddr=$(f_getNET_RANGE "$1"); netname=$(f_getNETNAME)
    if [ $option_detail != "0" ]; then
      netdescr=$($JQ '.data.records[]? | .[] | select (.key=="descr") | .value' $temp/whois.json | head -1)
    fi
    [[ -n "$netdescr" ]] || netorg=$(f_getORG_NAME)
    if [ $rir = "arin" ]; then
      handle=$($JQ '.data.records[]? | .[] | select (.key=="NetHandle") | .value' $temp/whois.json | tail -1)
      if [ $option_detail = "0" ]; then
        [[ $net_report2 = "1" ]] || [[ $net_report2 = "3" ]] && $WHOIS -h whois.arin.net -- "z + > ! $handle" > $temp/whois
      else
         $WHOIS -h whois.arin.net -- "z + > ! $handle" > $temp/whois
      fi
    else
      admin_c=$($JQ '.data.records[]? | .[] | select (.key=="admin-c") | .value' $temp/whois.json | head -3 | sort -u)
      ctry=$($JQ '.data.records[0]? | .[] | select (.key=="country") | .value' $temp/whois.json)
      org=$(jq -r '.data.records[]? | .[] | select (.key=="org") | .value' $temp/whois.json | head -1)
      [[ -n "$org" ]] && whois -h whois.$rir.net -- "--no-personal $org" > $temp/org && print_org=$(f_ORG_SHORT "$temp/org")
    fi
    if [ $option_detail = "0" ]; then
      origin=$(f_VALUE ":" "$(grep -sE '^Origin-AS:' $temp/pwhois)")
      if [ $rir = "arin" ]; then
        echo -e "\n+   $netaddr | $netname | $netorg | $(f_toUPPER "$rir")\n"
      elif [ $rir = "lacnic" ]; then
        echo -e "\n+   $netaddr | $netorg | $(f_toUPPER "$rir")\n"
      else
        echo -e "\n+   $netaddr | $netname | $ctry | $(f_toUPPER "$rir")\n"
        [[ -n "$origin" ]] && as_org=$(f_VALUE ":" "$(grep -sE '^AS-Org-Name:' $temp/pwhois)")
      fi
      if [ -n "$origin" ]; then
        echo -e "*>  $(f_VALUE ":" "$(grep -sE '^Prefix:' $temp/pwhois)")  (AS $origin)  $as_org\n"
      else
        echo -e "*>  Not announced\n"
      fi
      f_NET_DETAILS "$1"
    else
      if [ -n "$ctry" ]; then
        net_out="$netaddr | $netname | $ctry | $(f_toUPPER "$rir")"
      else
        net_out="$netaddr | $netname | $(f_toUPPER "$rir")"
      fi
      echo -e "Net:          $net_out"
      [[ -n "$netdescr" ]] && [[ -z "$org" ]] && echo -e "\nDescr:        $netdescr"
      if [ -n "$print_org" ]; then
        echo -e "\nOrg:          $print_org"
      else
        [[ -n "$netorg" ]] && echo -e "\nOrg:          $netorg"
      fi
      if [ $target_type != "hop" ]; then
        [[ -n "$netdescr" ]] && [[ -n "$print_org" ]] && echo ''
      fi
      [[ $target_type != "hop" ]] && f_ROUTE && f_Long
      if [ $rir = "arin" ]; then
        f_POC "$temp/whois"
      else
        if [ $option_detail = "1" ]; then
          if [ -n "$admin_c" ]; then
            if [ $rir = "apnic" ] && [[ "$admin_c" =~ "JNIC1-AP" ]]; then
              f_JPNIC_WHOIS "$($JQ '.data.records[]? | .[] | select (.key=="admin-c") | .value' $temp/whois.json | tail -1)"; echo ''
            else
              for ac in $(echo "$admin_c" | sort -u); do echo ''; f_ADMIN_C "$ac"; done
            fi
          fi
        elif [ $option_detail = "2" ]; then
          $TOUT 10 $WHOIS -h whois.$rir.net -- "-B $1" > $temp/whois
          echo ''; f_POC "$temp/whois" && f_getRIR_OBJECTS "$temp/whois"
        fi
      fi
    fi
  fi
fi
}

f_NET_OUTPUT(){
local whois_file="$*"
f_getNETS "$whois_file" > $temp/nettmp
if [ $target_type = "other" ]; then
    grep -sEa "^inet(6)?num:|^netname:|^descr:|^country:|^org:|^admin-c:|^mnt-by:|^source:" $temp/nettmp > $temp/nettmp2
elif [ $target_type = "iwhois_target" ]; then
  grep -sEa "^inet(6)?num:|^netname:|^country:|^org:|^admin-c:|^tech-c:|^mnt-by:" $temp/nettmp > $temp/nettmp2
elif [ $target_type = "whois_target" ]; then
    grep -sEa "^inet(6)?num:|^netname:|^descr:|^country:|^org:|(^abuse|^admin|^tech)-c:|^mnt-by:|^status:" $temp/nettmp > $temp/nettmp2
else
    grep -sEa "^inet(6)?num:|^netname:|^descr:|^country:|^org:|(^abuse|^admin|^tech)-c:|^mnt-by:" $temp/nettmp > $temp/nettmp2
fi
if [ $target_type = "iwhois_target" ]; then
sed '/inetnum:/i nnn' $temp/nettmp2 | sed '/inet6num:/i nnn' | sed '/netname:/i < ' | sed '/org:/i | ORG~' |
sed '/admin-c:/i | ADMIN~' | sed '/tech-c:/i | TECH~' | sed '/abuse-c:/i | ABUSE-C~' | sed '/mnt-by:/i |' |
sed '/status:/i |' | sed '/created:/i |' | sed '/country:/i |' | sed '/descr:/i |' | cut -d ':' -f 2- |
sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' | sed 's/nnn/\n\n/g' | sed 's/~/:/g' | sort -u
else
sed '/inetnum:/i nnn' $temp/nettmp2 | sed '/inet6num:/i nnn' | sed '/netname:/i <' | sed '/org:/i | ORG~' |
sed '/admin-c:/i | ADMIN~' | sed '/tech-c:/i | TECH~' | sed '/abuse-c:/i | ABUSE-C~' | sed '/mnt-by:/i | MNT~' |
sed '/status:/i |' | sed '/created:/i |' | sed '/country:/i |' | sed '/descr:/i |' | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' |
tr '[:space:]' ' ' | sed 's/nnn/\n\n/g' | sed 's/~/:/g' | sort -u
fi
}


f_PRINT_NETS(){
local net_file="$*"
[[ -f $temp/subnets4 ]] && rm $temp/subnets4; [[ -f $temp/subnets6 ]] && rm $temp/subnets6; [[ -f $temp/cidrs ]] && rm $temp/cidrs
if [ -f $net_file ] && [[ $(grep -sEc "$IP4_ALT|$REGEX_NET6" $net_file) -gt 0 ]]; then
  inums=$(cut -s -d '<' -f 1 $net_file | grep -sE "$IP4_ALT" | awk '{print $1 $2 $3}')
  [[ $(grep -sEc "$REGEX_NET6" $net_file) -gt 0 ]] && grep -sE "$REGEX_NET6" $net_file > $temp/subnets6
  if [ -n "$inums" ]; then
    grep -sE "$IP4_ALT" $net_file | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n > $temp/tmp4
    while read line; do
      range=$(echo $line | grep -sa '<' | cut -d '<' -f -1 | grep -sEa "$IP4_ALT" | awk '{print $1 $2 $3}')
      if [ -n "$range" ]; then
        print_range=$(echo "$range" | sed 's/-/ - /'); print_net=$(echo "$line" | cut -d '<' -f 2-)
        cidr=$($IPCALC -r "$range" | sed '/deaggregate/d' | tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//')
        [[ -n "$cidr" ]] && echo "$cidr" >> $temp/cidrs
        if [[ $(f_countW "$cidr") -gt 0 ]] && [[ $(f_countW "$cidr") -lt 4 ]]; then
          echo -e "$print_range < $cidr $print_net"
        else
          echo -e "$print_range < $print_net"
        fi
      fi
    done < $temp/tmp4 >> $temp/subnets4
    print_cidrs=$(f_EXTRACT_NET4 "$temp/cidrs" | tr '[:space:]' ' ' | sed 's/ /  /g' | fmt -w 60)
    [[ $(f_countW "$print_cidrs") -gt 3 ]] && echo -e "\n$print_cidrs\n" && f_Long; echo -e "\n"
    if [ $target_type = "whois_target" ] || [ $target_type = "iwhois_target" ]; then
      sed 's/^/> /' $temp/subnets4 | sed 's/> /\n\n/' | sed 's/</\n\n/' | sed 's/( /(/' | sed 's/ )/)/' |
      sed 's/|/\n\n/' | sed '/./,$!d'
    else
      sed 's/^/> /' $temp/subnets4 | sed 's/> /\n\n/' | sed 's/</\n\n  NAME:/' | sed '/./,$!d'
    fi
    [[ -f $temp/subnets6 ]] && f_Long2
  fi
  if [ -f $temp/subnets6 ]; then
    print6=$(grep -sEo "$REGEX_NET6" $temp/subnets6 | tr '[:space:]' ' ' | fmt -s -w 60 | sed 's/ /  /g'; echo '')
    [[ $(f_countW "$print6") -gt 3 ]] && echo "$print6" && f_Long
    if [ $target_type = "whois_target" ] || [ $target_type = "iwhois_target" ]; then
      sed 's/^/> /' $temp/subnets6 | sed 's/> /\n\n/' | sed 's/</\n\n /' | sed 's/|/\n\n /'
    else
      sed 's/^/> /' $temp/subnets6 | sed 's/> /\n\n/' | sed 's/</\n\n  NAME:/'
    fi
  fi
  echo ''
fi
}

f_WHOIS_NET(){
local s="$*"
if [ $bogon = "TRUE" ]; then
  f_Long2; f_BOGON_INFO "$s"
else
  if [ $target_cat = "nethandle" ]; then
    $WHOIS -h whois.arin.net -- "z + > ! $s" > $temp/whois
    f_HEADLINE3 " [NET]  $s  |  ARIN  |  $file_date": f_NET_INFO > $temp/arin_net
    [[ -f $temp/arin_net ]] && cat $temp/arin_net
    f_POC "$temp/whois" > $temp/arin_pocs; echo '' >> $temp/arin_pocs
    [[ -f $temp/arin_pocs ]] && echo '' && f_HEADLINE2 "CONTACT\n" && cat $temp/arin_pocs
    cidr1=$(grep -sEa -m 1 "^CIDR:" $temp/whois | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | cut -d ' ' -f 1)
    [[ -n "$cidr1" ]] && f_ROUTE_CONS "$cidr1"
    f_RESOURCES_NETNAME "$s"; f_SUBNETS "$s"
  else
    f_get_RIPESTAT_WHOIS "$s"
    f_getRIR "$s"; timeout 20 $WHOIS -h whois.pwhois.org $1  > $temp/pwhois
    if [ $rir = "lacnic" ]; then
    [[ $option_detail = "0" ]] || $WHOIS -h whois.lacnic.net $s > $temp/whois; f_LACNIC_WHOIS "$s"; else
    if [ $option_detail = "0" ]; then
      f_NET_HEADER "$s"
    else
      if [ $rir = "arin" ]; then
        handle=$($JQ '.data.records[]? | .[] | select (.key=="NetHandle") | .value' $temp/whois.json | tail -1)
        if [ $option_detail = "2" ] || [ $option_detail = "3" ]; then
          $WHOIS -h whois.arin.net -- "z + > ! $handle" > $temp/whois
        else
          $WHOIS -h whois.arin.net -- "n ! $handle" > $temp/whois
        fi
      else
        if [ $rir = "ripe" ] && [ $target_cat = "net4" ]; then
          $CURL -s -m 10 --location --request GET "https://stat.ripe.net/data/address-space-usage/data.json?resource=$s" > $temp/su.json
        fi
        if [ $option_detail = "2" ]; then
          $WHOIS -h whois.$rir.net -- "-B $s" > $temp/whois
        else
          $WHOIS -h whois.$rir.net -- "--no-personal $s" > $temp/whois
        fi
      fi # $rir = arin ?
      netabuse=$(grep -sEa "^OrgAbuseEmail:|^% Abuse|^abuse-mailbox:" $temp/whois | grep -sEao "$REGEX_MAIL" | sort -u | tr '[:space:]' ' ' ; echo '')
      f_HEADLINE3 "[NET]  $s  (query)  -  $file_date"
      [[ -n "$netabuse" ]] && echo -e "[@]: $netabuse\n___\n"
      [[ -f $temp/whois ]] && f_NET_INFO "$s"
    fi # $option_detail = 0 ?
   fi # $rir = lacnic ?
   if [ $net_report = "false" ]; then
     f_ROUTE_CONS "$s"
   else
     if [ $option_detail = "2" ] || [ $option_detail = "3" ]; then
       f_NET_DETAILS "$s"
     fi
    fi
  fi # target_cat = nethandle ?
fi # BOGON = false
}

# ---------------------------------  RELATED RESOURCES:  SUBNETS  -----------------------------------------

f_SUBNETS(){
if [ $rir = "ripe" ]; then
  if ! [ -f  $temp/su.json ]; then
    $CURL -s -m 10 --location --request GET "https://stat.ripe.net/data/address-space-usage/data.json?resource=$1" > $temp/su.json
  fi
  if [ -f  $temp/su.json ]; then
    assignment_count=$($JQ -r '.data.assignments[].address_range?' $temp/su.json | wc -w)
    allocation_count=$($JQ '.data.allocations[].allocation' $temp/su.json | wc -w)
  else
   assignment_count=0; allocation_count=0
  fi
  if [[ $assignment_count -gt 0 ]] || [[ $allocation_count -gt 0 ]]; then
    f_HEADLINE2 "$1 ADDRESS SPACE USAGE\n" > $temp/subnets1
    jq -r '.data.ip_stats[] | {ST: .status, IPs: .ips}'  $temp/su.json | tr -d '{}",' | sed 's/^[ \t]*//;s/[ \t]*$//' |
    sed '/^$/d' | sed '/null/d' | sed '/ST:/i |' | tr '[:space:]' ' ' | sed 's/| /\n/' | sed 's/ST: //g' |
    sed 's/IPs:/- IPs:/g' >> $temp/subnets1; echo '' >> $temp/subnets1; echo '' > $temp/subnets2
    jq -r '.data.assignments | .[] | {RANGE: .address_range, NAME: .asn_name, STATUS: .status, PARENT: .parent_allocation}'  $temp/su.json |
    tr -d '{}",' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' | tr '[:space:]' ' ' | sed 's/RANGE: /\n\n/g' | sed 's/NAME:/\n\n /' |
    sed 's/STATUS:/|/' | sed 's/PARENT:/| Parent:/' | sed '/|/G' >> $temp/subnets2; echo '' >> $temp/subnets2
    cat $temp/subnets1
    if [[ $assignment_count -gt 51 ]] || [[ $allocation_count -gt 51 ]]; then
      cat $temp/subnets1 > ${outdir}/SUBNETS_${file_name}.txt; cat $temp/subnets2 >> ${outdir}/SUBNETS_${file_name}.txt
    else
      cat $temp/subnets2
    fi
  fi
elif [ $rir = "arin" ]; then
  if [[ $(grep -c "Subdelegations for" $temp/whois) -gt 0 ]]; then
    sed '/Subdelegations for/{x;p;x;}' $temp/whois | sed -e '/./{H;$!d;}' -e 'x;/Subdelegations for/!d' |
    grep -E "\(NET" > $temp/subdel
  fi
  [[ -f $temp/subdel ]] && subnets_total=$(grep -Ec "\(NET" $temp/subdel)
  if [[ $subnets_total -gt 0 ]]; then
    echo '' > $temp/subnets1; f_HEADLINE2 "SUBDELEGATIONS for $s:  $subnets_total\n" >> $temp/subnets1
    sed '/(/{x;p;x;}' $temp/subdel | sed 's/(/\n\n(/' | sed 's/^ *//' | sed '/)/G' >> $temp/subnets2
    cat $temp/subnets1
    if [[ $subnets_total -lt 81 ]] ; then
      cat $temp/subnets2
   else
     cat $temp/subnets1 > ${outdir}/SUBNETS_${file_name}.txt; cat $temp/subnets2 >> ${outdir}/SUBNETS_${file_name}.txt;
   fi
  fi
fi
}

# ---------------------------------  RELATED RESOURCES:  NETWORKS BY NAME  -----------------------------------------

f_ALL_SOURCES_WHOIS(){
$TOUT 20 $WHOIS -h whois.ripe.net -- "--no-personal -a $1" |
sed -e '/./{H;$!d;}' -e 'x;/IANA1-RIPE/d' | sed -e '/./{H;$!d;}' -e 'x;/IANA-BLK/d' |
sed 's/-GRS//' | sed 's/# Filtered//' | grep -saEv "DUMY-RIPE|RIPE-NCC-HM-MNT|RIPE-NCC-LEGACY-MNT|RIPE-NCC-END-MNT" |
sed '/source:/G' > $temp/all_sources_tmp
sed -e '/./{H;$!d;}' -e 'x;/netname:/!d' $temp/all_sources_tmp > $temp/all_sources
echo '' >> $temp/all_sources
sed -e '/./{H;$!d;}' -e 'x;/org-name:/!d' $temp/all_sources_tmp >> $temp/all_sources
echo '' >> $temp/all_sources
sed -e '/./{H;$!d;}' -e 'x;/route:/!d' $temp/all_sources_tmp >> $temp/all_sources
echo '' >> $temp/all_sources
f_EXTRACT_EMAIL "$temp/all_sources_tmp" >> $temp/all_sources
}

f_DEAGGREGATE(){
if [[ $(grep -sEc "$IP4_ALT" $temp/netlist_tmp) -lt 500 ]]; then
  if [ $target_type = "arin_iwhois" ]; then
     grep -sE "$IP4_ALT" $temp/netlist_tmp | tr -d ' ' > $temp/v4ranges_tmp
  else
    cut -s -d '|' -f -1 $temp/netlist_tmp | grep -sE "$IP4_ALT" | tr -d ' ' > $temp/v4ranges_tmp
  fi
  for r in $(cat $temp/v4ranges_tmp); do
    ip_calc=$($IPCALC -r $r); calc_count=$(echo "$ip_calc" | grep -sEo "$IP4_NET_ALT" | wc -w)
    if [[ $calc_count -gt 0 ]]; then
      if [[ $calc_count -eq 1 ]]; then
        echo "$ip_calc" | grep '/'
      else
        echo "$ip_calc" | sed '/deaggregate/a ->' | tr '[:space:]' ' '  | sed 's/deaggregate /\n/' | sed 's/->/\n ->/' |
        sed 's/ /  /g' | sed 's/  -  / - /'; echo ''
      fi
    fi
  done > $temp/deag_tmp
  if [ -f $temp/deag_tmp ]; then
    single_deaggregates=$(grep -sEv "\-|\->" $temp/deag_tmp | grep -sEo "$IP4_NET_ALT")
    multiple_deaggregates=$(grep -sE "\-|\->" $temp/deag_tmp)
    if [ -n "$multiple_deaggregates" ]; then
      deag_count=$(grep -sEo "$IP4_NET_ALT" $temp/deag_tmp | wc -w)
      echo -e "\n  * $deag_count deaggregates from $(grep -sEoc "$IP4_ALT" $temp/netlist_tmp) networks *\n\n"
   fi
    [[ $(f_countW "$single_deaggregates") -eq 1 ]] && echo "  $single_deaggregates"
    if [[ $(f_countW "$single_deaggregates") -gt 1 ]]; then
      echo "$single_deaggregates" | tr '[:space:]' ' ' | sed 's/ /  /g' | fmt -w 60 | sed 's/^/  /'; echo ''
    fi

    if [[ $(f_countW "$multiple_deaggregates") -gt 1 ]]; then
      [[ -n "$single_deaggregates" ]] && echo ''
      echo -e "  Networks with multiple deagreggates:\n"
      echo -e "$multiple_deaggregates" | sed 's/->/  ->/' | sed '/->/{x;p;x;G}' | sed 's/^/  /'
    fi
  fi
else
  grep -sE "$IP4_ALT" $temp/netlist_tmp
fi
[[ -f $temp/netlist_tmp ]] && rm $temp/netlist_tmp; [[ -f $temp/deag_tmp ]] && rm $temp/deag_tmp
[[ -f $temp/v4ranges_tmp ]] && rm $temp/v4ranges_tmp
}

f_RESOURCES_NETNAME(){
local name="$*"
netcount=""; netcount4=""; netcount6=""; admins_other=""; nets4=""; echo "$n" > $temp/netnames
if [ $rir = "arin" ]; then
  admins_other=''
  $WHOIS -h whois.ripe.net -- "--no-personal -a $name" | grep -E "%|:" | sed 's/-GRS//' | sed 's/# Filtered//' |
  sed '/inetnum:/{x;p;x;}' | sed '/inet6num:/{x;p;x;}' | sed '/source:/G' | sed -e '/./{H;$!d;}' -e 'x;/IANA1-RIPE/d' |
  sed -e '/./{H;$!d;}' -e 'x;/netname:/!d' | sed -e '/./{H;$!d;}' -e 'x;/ARIN/!d' |
  grep -sE "^inet(6)?num:|^netname:|^org:|^source:" | sed '/source:/G' | grep -v 'source:' > $temp/nets
else
  $TOUT 10 $WHOIS -h whois.$rir.net -- "--no-personal $name" > $temp/nets_tmp
  f_getNETS4 "$temp/nets_tmp" | tee $temp/nets > $temp/nets4
  f_getNETS6 "$temp/nets_tmp" | tee -a $temp/nets > $temp/nets6
fi
netcount=$(grep -sEc "^inet(6)?num:" $temp/nets); netcount4=$(grep -sc '^inetnum:' $temp/nets)
if [[ $netcount -gt 0 ]]; then
  if [ $rir != "arin" ] && [ $target_type = "net" ]; then
    if [ -f $temp/whois ]; then
      grep -Eas "^admin-c:|^nic-hdl:" $temp/whois | awk '{print $NF}' | tr -d ' ' > $temp/nic_hdls
      cat $temp/nic_hdls | tr -d ' ' | sed '/^$/d' | sort -u > $temp/nh_list1
    fi
    f_VALUE ":" "$(grep -sa '^admin-c:' $temp/nets)" | sort -u > $temp/nh_list2
    if [ -f $temp/nh_list1 ] && [ -f $temp/nh_list2 ]; then
      admins_other=$(comm -1 -3 $temp/nh_list1 $temp/nh_list2_sorted | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' | head -5)
    fi
  fi
  f_sortNETS "$name"
  if [ -n "$admins_other" ]; then
    f_Short; echo -e "\nOTHER CONTACTS FOR '$name'"  # ---  GET ADDITIONAL ADMIN CONTACTS  ---
    for i in $admins_other; do
      $WHOIS -h whois.$rir.net -- "-r -F $i" | tr -d '*' | sed 's/^ *//' > $temp/acwhois
      grep -E "^pn:|^ro:|^ad:|^ph:|^nh:" $temp/acwhois | sed '/pn:/i nnn' | sed '/ro:/i nnn' | sed '/pn:/a nnn' | sed '/ro:/a nnn' |
      sed '/ph:/i |' | sed '/nh:/i | ' | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' | sed 's/nnn/\n\n/g' |
      sed 's/^ *//' | sed 's/^| //'
    done > $temp/admins_other; [[ -f $temp/admins_other ]] && cat $temp/admins_other
  fi
  [[ -f $temp/nets ]] && rm $temp/nets; [[ -f $temp/nets4 ]] && rm $temp/nets4; [[ -f $temp/nets6 ]] && rm $temp/nets6
fi
}

f_sortNETS(){
local name="$*"
[[ -f $temp/tmp ]] && rm $temp/tmp; [[ -f $temp/print4 ]] && rm $temp/print4; [[ -f $temp/print6 ]] && rm $temp/print6
inums=""; outfile_alt="${outdir}/NET_RANGES.${name}.txt"
if [ $rir = "arin" ]; then
  [[ -f $temp/arin_nets ]] && netcount=$(grep -c 'netname:' $temp/arin_nets) || netcount=0
  if [[ $netcount -gt 0 ]]; then
    [[ $target_type = "net" ]] || f_Medium
    grep -sE "^inet(6)?num:|^netname:|^org:" $temp/arin_nets |
    sed '/inetnum:/i ==' | sed '/inet6num:/i ==' | sed '/netname:/i |' | sed '/org:/i |' | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' |
    tr '[:space:]' ' ' | sed 's/== /\n/g' | cut -d '|' -f -3 | grep -wi "$name" | tr -d ' ' > $temp/tmp; echo '' >> $temp/tmp
    net_orgs=$(cut -s -d '|' -f 2 $temp/tmp | sort -uV); net_org_count=$(f_countW "$net_orgs")
    print_owners=$(echo "$net_orgs" | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^[ \t]*//;s/[ \t]*$//')
    netcount4=$(grep -sEc "$IP4_ALT" $temp/tmp); netcount6=$(grep -sEc "$REGEX_NET6" $temp/tmp)
    [[ $netcount4 -gt 42 ]] && print_netcount4="$netcount4 (see file)" || print_netcount4="$netcount4"
    [[ $netcount6 -gt 32 ]] &&  print_netcount6="$netcount6 (see file)"  || print_netcount6="$netcount6"
    if [ $domain_enum = "true" ]; then
      echo -e "\n'$name' Networks (global): $netcount\n"
    else
      [[ $target_type = "net" ]] && f_HEADLINE2 "RESOURCES FOR '$name' (networks: $netcount)\n"
      [[ $target_type = "other" ]] && echo -e "\nARIN NETWORK RESOURCES FOR $name:  $netcount\n"
    fi
    echo -e "  IPv4: $print_netcount4, IPv6: $print_netcount6\n"
    echo -e "  Owners: $print_owners\n"
    if [[ $netcount4 -gt 0 ]]; then
      grep -sE "$IP4_ALT" $temp/tmp | sed 's/|/ | /g' > $temp/tmp4
      for o in $net_orgs; do
        grep -w "$o" $temp/tmp4 > $temp/netlist_tmp; inums=$(f_DEAGGREGATE)
        if [ -n "$inums" ]; then
         f_Medium
          [[ $net_org_count -gt 1 ]] && echo -e "\n  Owner: $o\n"; echo -e "$inums\n"
        fi
       done > $temp/print4
    fi
    if [[ $netcount6 -gt 0 ]]; then
      grep -sE "$REGEX_NET6" $temp/tmp | sed 's/|/ | /g' > $temp/tmp6
      for o in $net_orgs; do
        grep -w "$o" $temp/tmp > $temp/org_nets; inums6=$(grep -sEo "$REGEX_NET6" $temp/org_nets)
        if [ -n "$inums6" ]; then
          f_Medium
          [[ $net_org_count -gt 1 ]] && echo -e "\n  Owner: $o\n"
          echo -e "\n$inums6" | tr '[:space:]' ' ' | sed 's/ /  /g' | fmt -w 60; echo ''
        fi
      done > $temp/print6
    fi
  fi
else
  rir_caps=$(f_toUPPER "$rir")
  grep -sEav "^status:|^remarks:|^tech-c:|^created:|^last-modified:" $temp/nets |
  grep -sE "^inet(6)?num:|^netname:|^org:|^abuse-c:|^admin-c:|^country:|mnt-by:|^source:" |
  sed '/source:/G' | sed '/inetnum:/i ==' | sed '/inet6num:/i ==' | sed '/netname:/i | NAME~' | sed '/org:/i | ORG~' |
  sed '/country:/i | CC~' | sed '/admin-c:/i | ADMIN~' | sed '/abuse-c:/i | ABUSE~' | sed '/mnt-by:/i | MNT~' |
  sed '/source:/i |' | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' | sed 's/== /\n\n/g' |
  sed 's/~/:/g' | grep -wi "$name" > $temp/tmp; echo '' >> $temp/tmp
  [[ -f $temp/tmp ]] && netcount=$(grep -c '|' $temp/tmp) || netcount=0
  netcount4=$(grep -sEac "$IP4_ALT" $temp/tmp); netcount6=$(grep -sEac "$REGEX_NET6" $temp/tmp)
  if [[ $netcount -gt 0 ]]; then
    [[ $netcount4 -gt 42 ]] && print_netcount4="$netcount4 (see file)" || print_netcount4="$netcount4"
    [[ $netcount6 -gt 32 ]] &&  print_netcount6="$netcount6 (see file)"  || print_netcount6="$netcount6"
    grep -sEa "^inet(6)?num:|^netname:|^country:|^admin-c:|^abuse-c:" $temp/nets |
    sed '/inetnum:/i ==' | sed '/inet6num:/i ==' | sed '/netname:/i |' | sed '/country:/i |' | sed '/admin-c:/i |' |
    sed '/abuse-c:/i |' | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' |
    tr '[:space:]' ' ' | sed 's/== /\n/g' | cut -d '|' -f -4 | grep "$name" | tr -d ' '  > $temp/tmp1; echo '' >> $temp/tmp1
    net_admins=$(cut -s -d '|' -f 3,4 $temp/tmp1 | sed 's/|/ | /g' | grep -sEo "\b[0-9A-Z\-]{4,27}\b" | sort -uV)
    admins_total=$(f_countW "$net_admins"); abusec_count=$(grep -v 'ADMIN:' $temp/tmp | grep -c 'ABUSE-C:')
    admin_count=$(grep -c 'ADMIN:' $temp/tmp); net_orgs=$(grep -soP "ORG:\K.*?(?=\|)" $temp/tmp | tr -d ' ' | sort -uV)
    org_count=$(f_countW "$net_orgs"); net_mnt=$(grep -soP "MNT:\K.*?(?=\|)" $temp/tmp | tr -d ' ' | sort -uV); mnt_count=$(f_countW "$net_mnt")
    net_cc=$(grep -soP "CC:\K.*?(?=\|)" $temp/tmp | tr -d ' ' | sort -u); cc_count=$(f_countW "$net_cc")
    print_netcc=$(echo "$net_cc" | grep -sEo "[A-Z]{2,3}" | sort -u | tr '[:space:]' ' ' | sed 's/ /  /g'; echo '')
    if [[ $org_count -gt 1 ]]; then
      owner_guess="  Networks owned by $org_count (+) parties."
    elif [[ $admins_total -eq 1 ]]; then
      owner_guess="  All networks owned by the same party."
    elif [[ $admins_total -gt 1 ]]; then
      if [[ $mnt_count -eq 1 ]]; then
        owner_guess="  Multiple admin/abuse contacts, but a single maintainer."
      else
        owner_guess="  Multiple admin/abuse contacts and maintainers:\n\n  Networks likely owned by multiple parties."
      fi
     fi
     [[ $target_type = "net" ]] || f_Medium
     if [ $domain_enum = "true" ]; then
       echo -e "\n'$name' Networks (global): $netcount\n"
     else
       [[ $target_type = "net" ]] && f_HEADLINE2 " RESOURCES FOR '$name' (networks: $netcount)\n"
       [[ $target_type = "other" ]] && echo -e "\n $rir_caps NETWORK RESOURCES FOR '$name': $netcount\n"
     fi
     echo -e "  IPv4: $print_netcount4, IPv6: $print_netcount6"
     [[ $cc_count -gt 1 ]] || [[ $domain_enum = "false" ]] && echo ''
     echo -e "\n$owner_guess\n"
     [[ $cc_count -gt 1 ]] || [[ $domain_enum = "false" ]] && echo -e "  Registration countries: $print_netcc\n"
     if [[ $netcount4 -gt 0 ]]; then
       grep -sE "$IP4_ALT" $temp/tmp1 | sed 's/|/ | /g' > $temp/tmp4
       admins4=$(cut -s -d '|' -f 3,4 $temp/tmp4 | grep -sEo "\b[0-9A-Z\-]{4,27}\b" | sort -uV)
       for ac in $admins4; do
         grep -w "$ac" $temp/tmp4 > $temp/netlist_tmp
         if [ -f $temp/netlist_tmp ]; then
           [[ -f $temp/netlist_tmp ]] && inums=$(f_DEAGGREGATE)
           if [ -n "$inums" ]; then
             f_Medium
             echo -e "\n  Responsible: $ac\n"; echo -e "$inums\n"; inums=""
            fi
         fi
        done > $temp/print4
      fi # netcount4 -gt 0
      if [[ $netcount6 -gt 0 ]]; then
        grep -sE "$REGEX_NET6" $temp/tmp1 | sed 's/|/ | /g' > $temp/tmp6
        admins6=$(cut -s -d '|' -f 3,4 $temp/tmp6 | grep -sEo "\b[0-9A-Z\-]{4,27}\b" | sort -uV)
        for ac in $admins6; do
          grep -w "$ac" $temp/tmp6 > $temp/netlist_tmp
          if [ -f $temp/netlist_tmp ]; then
            inums6=$(grep -sEo "$REGEX_NET6" $temp/netlist_tmp)
            if [ -n "$inums6" ]; then
              f_Medium
              echo -e "\n  Responsible: $ac\n"
              echo -e "\n$inums6" | tr '[:space:]' ' ' | sed 's/ /  /g' | fmt -w 60; inums6=""
            fi
          fi
        done > $temp/print6
     fi # netcount6 -gt 0
   fi # netcount -gt 0
fi # rir = ?
if [[ $netcount4 -gt 42 ]] || [[ $netcount6 -gt 32 ]]; then
  f_HEADLINE3 "[NET]  $name | $(f_toUPPER "$rir") |  $file_date" > ${outdir}/NET_RANGES.${name}.txt
  echo -e "\n  IPv4: $netcount4, IPv6: $netcount6\n" >> ${outdir}/NET_RANGES.${name}.txt
fi
if [[ $netcount4 -gt 0 ]]; then
  [[ $netcount4 -lt 43 ]] && cat $temp/print4 || cat $temp/print4 >> ${outdir}/NET_RANGES.${name}.txt
fi
if [[ $netcount6 -gt 0 ]]; then
  [[ $netcount6 -lt 33 ]] && cat $temp/print6 || cat $temp/print6 >> ${outdir}/NET_RANGES.${name}.txt
fi
}

# ---------------------------------  RELATED RESOURCES: ADDESS SPACE HIERARCHY -----------------------------------------

f_getLESS_SPECIFICS(){
local s="$*"
$TOUT 10 $WHOIS -h whois.$rir.net -- "--no-personal -L $s" > $temp/l_specifics
echo -e "\nLESS SPECIFICS, EXACT\n\n"
grep -B 1 "IANA-BLK" $temp/l_specifics | cut -d ':' -f 2- | sed '/IANA/{x;p;x;}' | sed 's/^ *//'
count_lp=$(sed -e '/./{H;$!d;}' -e 'x;/IANA/d' $temp/l_specifics | grep -c '^netname:')
if [[ $count_lp -gt 0 ]]; then
  f_NET_OUTPUT "$temp/l_specifics" > $temp/lp
  f_PRINT_NETS "$temp/lp"; sed -e '/./{H;$!d;}' -e 'x;/IANA/d' $temp/l_specifics > $temp/lp_org
  [[ $(grep -ac '^org-name:' $temp/lp_org) -gt 0 ]] && f_Long2 && f_ORG_SHORT "$temp/lp_org"
fi
}

f_getMORE_SPECIFICS(){
local s="$*"
[[ -f $temp/whois_nets ]] && rm $temp/whois_nets
$TOUT 20 $WHOIS -h whois.$rir.net -- "--no-personal -M $s" > $temp/m_specifics
netcount=$(grep -sEac "^netname:" $temp/m_specifics)
if [[ $netcount -gt 0 ]]; then
  sed -e '/./{H;$!d;}' -e 'x;/netname:/!d' $temp/m_specifics | grep -sEa -A 1 "^inetnum:|^netname:|^country:|^admin-c:|^status:|^mnt-by:|^source:" |
  sed '/--/d' | grep -sEav "^created:|^abuse-c:|^tech-c:|^remarks:" | sed '/source:/G' | grep -v 'source:' | sed '/inetnum:/i ==' |
  sed '/netname:/i <' | sed '/country:/i |' | sed '/descr:/i |' | sed '/admin-c:/i |' | sed '/status:/i |' |
  sed '/mnt-by:/i |' | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' | sed 's/== /\n\n/g' > $temp/msp_tmp
  echo '' >> $temp/msp_tmp
  if [ $option_filter = "y" ]; then
    for f in $(cat $temp/filters); do
      f_HEADLINE2 "MORE SPECIFICS, FILTER: $f\n"
      grep -sEai "${f}.*|*.${f}.*" $temp/msp_tmp > $temp/tmp
      [[ -f $temp/whois_nets ]] && count_filtered=$(grep -sEac '|' $temp/tmp) || count_filtered=0
      echo -e "Networks: $count_filtered\n________\n\n"
    done
  else
    f_HEADLINE2 "MORE SPECIFICS  (NETWORKS: $netcount)\n" ; cat $temp/msp_tmp > $temp/tmp
  fi
  f_PRINT_NETS "$temp/tmp" | sed '/|/G'
fi
}

# ---------------------------------  RELATED RESOURCES: MORE/LESS SPECIFIC PREFIXES  -----------------------------------------

f_RELATED(){
if [ $target_type = "prefix" ]; then
  pfx=$($JQ '.data.resource' $temp/pov.json)
else
  pfx=$(grep -sE "^Prefix:" $temp/pwhois | awk '{print $NF}' | tr -d ' ')
fi
$CURL -s "https://stat.ripe.net/data/related-prefixes/data.json?resource=${pfx}" > $temp/rel.json
related=$($JQ '.data.prefixes[] | {A: .origin_asn, N: .asn_name, P: .prefix, R: .relationship}' $temp/rel.json | tr -d '{",}' |
sed 's/^ *//' | sed '/^$/d' | tr '[:space:]' ' ' | sed 's/A: /\n\nAS/g' | sed 's/N:/-/g' | sed 's/R:/|/g' | sed 's/P:/|/g')
if [ -n "$related" ] ; then
  [[ $target_type = "prefix" ]] && f_HEADLINE2 "RELATED PREFIXES\n" || f_HEADLINE2 "RELATED PREFIXES  ($pfx)\n" 
  less_sp=$(echo "$related" | grep -w 'Overlap - Less Specific'); more_sp=$(echo "$related" | grep -w 'Overlap - More Specific')
  adjacent=$($JQ '.data.prefixes[] | {P: .prefix, AS: .origin_asn, N: .asn_name, R: .relationship}' $temp/rel.json  | tr -d '{,"}' |
  sed 's/^ *//' | sed '/^$/d' | tr '[:space:]' ' ' | sed 's/P: /\n/g' | sed 's/AS:/| AS/g' | sed 's/N:/-/g' | sed 's/R:/|/g')
  adj_left=$(echo "$adjacent" | grep -w 'Adjacency - Left'); adj_right=$(echo "$adjacent" | grep -w 'Adjacency - Right')
  rel_asn=$($JQ '.data.prefixes[].origin_asn' $temp/rel.json | sort -ug)
  if [ -n "$adj_left" ] ; then
    echo -e "\nAdjacent Left\n\n" ; echo "$adj_left" | sed '/|/G' | cut -d '|' -f -2 | sed 's/| AS:/- AS/g'
  fi
  if [ -n "$adj_right" ] ; then
    echo -e "\nAdjacent Right\n\n"; echo "$adj_right" | sed '/|/G' | cut -d '|' -f -2 | sed '/|/G' | sed 's/| AS:/- AS/g'
  else
    [[ -n "$less_sp" ]] || [[ -n "$more_sp" ]] && echo ''
  fi
  if [ -n "$less_sp" ] ; then
    echo -e "Less Specific\n"
    for r_as in $rel_asn ; do
      lp_sorted=$(echo "$less_sp" | grep -w -E "AS${r_as}")
      if [ -n "$lp_sorted" ] ; then
        echo ''; echo "$less_sp" | grep -w -E -m 1 "AS${r_as}" | cut -d '|' -f 1 | sed 's/AS/AS /g' ; echo ''
        lp_out=$(echo "$less_sp" | grep -w -E "AS${r_as}" | cut -d '|' -f 2 | sed 's/^ *//' | tr '[:space:]' ' ')
        echo -e "$lp_out\n" | fmt -s -w 80
      fi
    done
    [[ -n "$more_sp" ]] && echo ''
  fi
  if [ -n "$more_sp" ] ; then
    echo -e "\nMore Specific\n"
    for r_as in $rel_asn ; do
      mp_sorted=$(echo "$more_sp" | grep -w -E "AS${r_as}")
      if [ -n "$mp_sorted" ] ; then
        echo ''; echo "$more_sp" | grep -w -E -m 1 "AS${r_as}" | cut -d '|' -f 1 | sed 's/AS/AS /g' ; echo ''
        mp_out=$(echo "$more_sp" | grep -w -E "AS${r_as}" | cut -d '|' -f 2 | sed 's/^ *//' | tr '[:space:]' ' ')
        echo -e "$mp_out\n" | fmt -s -w 80 
      fi 
    done
  fi
fi
}

# ---------------------------------  NETWORK IP GEOLOCATION & ALLOCATION COUNTRY  -----------------------------------------

f_NETGEO(){
local g="$*"
if [[ ${g} =~ "-" ]]; then
  geo_target=$(echo $g | cut -d '-' -f 1 | tr -d ' ')
else
  geo_target="$g"
fi
$CURL -s -m 7 --location --request GET "https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource=${geo_target}" > $temp/netgeo.json
geo_max=$($JQ '.data.located_resources[] | .locations[].country' $temp/netgeo.json | sort -u | tr '[:space:]' ' ' |
sed 's/^[ \t]*//;s/[ \t]*$//'); geo_count=$(f_countW "$geo_max")
geo_rir=$($CURL -s -m 7 --location --request GET "https://stat.ripe.net/data/rir-geo/data.json?resource=${geo_target}" |
$JQ '.data.located_resources[].location' | tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//')
if [ $rir = "arin" ] || [ $rir = "lacnic" ]; then
  geo_whois=""
else
  geo_whois=$(grep -E "^country:" $temp/whois | awk '{print $NF}' | head -1)
fi
if [[ $geo_count -gt 0 ]]; then
  if [[ $geo_count -lt 12 ]]; then
    [[ -n "$geo_whois" ]] && echo "$geo_rir (RIR),  $geo_whois (whois),  $geo_max (maxmind)" || echo "$geo_rir (RIR),  $geo_max (maxmind)"
  elif [[ $geo_count -gt 11 ]]; then
    [[ -n "$geo_whois" ]] && echo "$geo_rir (RIR),  $geo_whois (whois),  $geo_max (maxmind)" || echo "$geo_rir (RIR),  $geo_count countries (maxmind)"
  fi
else
  [[ -n "$geo_whois" ]] && echo "$geo_rir (RIR),  $geo_whois (whois)" || echo "$geo_rir (RIR)"
fi
}

f_NETGEO_MAXMIND(){
[[ -f $temp/netgeo.json ]] || $CURL -s https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource=$1 > $temp/netgeo.json
$JQ '.data.located_resources[].locations | .[] | .resources[]' $temp/netgeo.json | sort -u -V > $temp/nets_geo.list
netcount=$(cat $temp/nets_geo.list | wc -w); locations=$($JQ '.data.located_resources[].locations | .[]' $temp/netgeo.json)
f_HEADLINE2 "GEOGRAPHIC DISTRIBUTION" | tee $temp/geo_header
echo "$locations" | $JQ '{N: .resources[], Lat: .latitude, Lon: .longitude, cov: .covered_percentage, Country: .country, C: .city}' |
tr -d '{,"}' | sed 's/^ *//' | sed '/^$/d' | tr '[:space:]' ' ' | sed 's/N: /\n\n/g' | sed 's/ Lon: /\,/g' | sed 's/Lat:/ -  Lat\/Lon:/g' |
sed 's/cov:/(covered:/g' | sed 's/Country:/%) | Country:/g' | sed 's/C://g' > $temp/geo_tmp; echo '' >> $temp/geo_tmp
if [ $netcount -gt "3" ]; then
  [[ $netcount -gt "3" ]] && echo -e "\n_______________________________________\n" >> $temp/geo_tmp || echo '' >> $temp/geo_tmp
  cat $temp/nets_geo.list | tr '[:space:]' ' ' | fmt -s -w 40 | sed 's/ /  /g' | sed 's/^ *//' >> $temp/geo_tmp
fi
echo '' >> $temp/geo_tmp
if [[ $netcount -gt 51 ]] ; then
  echo -e "\nOutput has been written to file ($netcount networks)"; cat $temp/geo_header > ${outdir}/NETGEO_${file_name}.txt
  cat $temp/geo_tmp >> ${outdir}/NETGEO_${file_name}.txt
else
  cat $temp/geo_tmp
fi; rm $temp/netgeo.json; rm $temp/geo_tmp
}

# ---------------------------------  NETWORK CVES  -----------------------------------------

f_NET_CVEs(){
[[ -f $temp/net_ports ]] && rm  $temp/net_ports
echo ''; f_HEADLINE3 "[NET]  $1  CPEs/VULNERS  (SOURCE: SHODAN API)  $file_date"; echo ''
for c in $($NMAP -sL -Pn -sn -n "$1" | grep 'Nmap scan report' | awk '{print $NF}' | sed '/1,1/d' | sed '$d'); do
  f_CVES "$c"
done
}

# ---------------------------------  PING SWEEP  -----------------------------------------

f_PING_SWEEP(){
[[ $option_enum = "1" ]] && echo '' && f_HEADLINE2 "$1  PING SWEEP\n"
if [ $option_scope = "1" ] && [ $option_pingsweep = "0" ]; then
  [[ -n "$is_admin" ]] && ${run_as_sudo} $NMAP -sn $1  > $temp/pingsweep || $NMAP -sn $1 > $temp/pingsweep
  grep -E "Nmap scan report|Host is|rDNS|MAC Address:|Nmap done:" $temp/pingsweep | sed '/Nmap scan report/i nnn' |
  sed 's/Nmap scan report for/*/' | sed '/Host is/i ==' | tr '[:space:]' ' ' | sed 's/nnn/\n\n\n/g' | sed 's/==/\n\n/' |
  sed 's/MAC Address:/| MAC:/' | sed 's/Host is up/  UP/' | sed 's/Nmap done:/\n  /' | sed 's/)./)/' | sed 's/)scanned/) scanned/' |
  sed '/scanned/i\\n   _______________________________________________________\n'; echo -e "\n"
else
if [ $option_pingsweep = "1" ]; then
  ps_options=''
elif [ $option_pingsweep = "2" ]; then
  echo -e "21\n22\n25\n80\n113\n443" > $temp/probes
  [[ $option_enum = "1" ]] && [[ -f $temp/net_ports ]] && cat $temp/net_ports >> $temp/probes
  port_probes=$(sort -ug $temp/probes | sort -R  | sed 's/^/,/' | tr '[:space:]' ' ' | sed 's/^ *//' | sed 's/^\,//' | tr -d ' ')
  ps_options="-PE -PP -PS${port_probes} -PA80,443,3389 -PU53,631,40125 -PY80,443,5060"
elif [ $option_pingsweep = "3" ]; then
 ps_options=${psweep_array[@]}
fi
if [ $option_root = "y" ] ; then
  sudo $NMAP $1 -n -sn ${ps_options} -oA ${out} > $temp/pingsweep.txt
else
  $NMAP $1 -n -sn ${ps_options} -oA ${out} > $temp/pingsweep.txt
fi
grep -E "^Nmap scan report|^Host is|^Nmap done" $temp/pingsweep.txt | tr '[:space:]' ' ' | sed 's/Nmap scan report for /\n/g' |
sed 's/Host is up/ - UP /g' > $temp/print_psweep
grep 'Nmap done:' $temp/print_psweep | sed '/Nmap done:/{x;p;x;G}' | sed 's/Nmap done: //'; echo ''
grep -v 'Nmap done:' $temp/print_psweep
f_Medium; echo -e "\nPROBES SEND:\n\n"
if [ $option_pingsweep = "1" ]; then
  [[ $option_root = "y" ]] && echo "-PE -PP -PS443 -PA80" || echo "-PA80,443"
else
  echo "$ps_options"; fi; echo -e "\n(-PE/PP: ICMP Echo/Timestamp, PS: TCP SYN,\nPA: TCP ACK, PU: UDP, PY: SCTP INIT)\n"
fi
}

# ---------------------------------  LOCAL NETWORK  -----------------------------------------

f_DUMP_ROUTER_DHCP_6(){
iflist6=$(ip -6 -br addr show up scope global | grep 'UP' | cut -d ' ' -f 1 | tr -d ' ' | sort -uV)
if ! type atk6-dump_router6 &> /dev/null; then
  f_Long; echo -e "\nNo executable found for atk6-dump_router6\n"
  if ! type atk6-dump_dhcp6 &> /dev/null; then
    f_Long; echo -e "\nNo executable found for atk6-dump_dhcp6\n"
  fi
else
  if [ -n "$iflist6" ]; then
    for i6 in $iflist6; do
      if type atk6-dump_router6 &> /dev/null; then
        f_HEADLINE2 "ROUTER SOLICITATION ($i6)\n"; $run_as_sudo $DUMP_ROUTER6 $i6 | sed '/Router:/{x;p;x;G}'; echo ''
      fi
      if type atk6-dump_dhcp6 &> /dev/null; then
        f_HEADLINE2 "DHCPv6 ($i6)\n"; $run_as_sudo $DUMP_DHCP6 $i6; echo ''
      fi
    done
  fi
fi
}

f_DUPLICATES(){
[[ -f $temp/duplicates ]] && rm $temp/duplicates
$run_as_sudo $NMAP -R --resolve-all --system-dns -PN -p 22,443,445 --script=duplicates,nbstat,ssl-cert,ssh-hostkey $x 2>/dev/null > $temp/duplicates
if [[ $(grep -c 'duplicates:' $temp/duplicates) -gt 0 ]]; then
  grep '|' $temp/duplicates | sed -n '/duplicates:/,$p' | sed '/|_/G' | tr -d '|_' | sed 's/^[ \t]*//;s/[ \t]*$//' |
  sed 's/duplicates:/POSSIBLE DUPLICATES \/ MULTIHOMED HOSTS DETECTED/' | sed '/ARP/{x;p;x;}' | sed '/SSH/{x;p;x;G}' |
  sed '/SSL/{x;p;x;G}' | sed '/Netbios/{x;p;x;G}' | sed 's/ARP/Method: ARP/' | sed 's/SSH/Method: SSH/' | sed 's/SSL/Method: SSL/' |
  sed 's/Netbios/Method: Netbios/' | sed '/MAC:/{x;p;x;G}' | sed '/Name:/G' > $temp/dup_tmp; cat $temp/dup_tmp
  ip_dups=$(f_EXTRACT_IP4 "$temp/dup_tmp"); mac_dups=$(grep -sEo "$REGEX_MAC" "$temp/dup_tmp")
  [[ -n "$ip_dups" ]] || [[ -n "$mac_dups" ]] && echo '' && f_Medium && echo ''
  if [ -n "$ip_dups" ]; then
    echo ''; for ip_dup in $ip_dups; do f_LOCAL_DNS "$ip_dup" | grep '\-'; done
  fi
  if [ -n "$mac_dups" ]; then
    echo ''; for mac_dup in $mac_dups; do mac_pfx=$(f_getMAC_PFX "$mac_dup"); [[ -n "$mac_pfx" ]] && echo -e "$mac_dup    $mac_pfx"; done; echo ''
  fi
else
  echo -e "No duplicates / multihomed systems found\n"
fi
}

#-------------------------------  NETWORK DNS  -------------------------------

f_NET_RDNS(){
[[ $netop = "1" ]] && echo '' && f_HEADLINE2 "$1  RDNS\n"
f_RESOLVE_HOSTS4 "$1"
if [ -f $temp/resolved4 ]; then
  if [ $rdnsv6 = "true" ]; then
    awk '{print $NF}' $temp/resolved4 | tr -d ' ' > $temp/rdns_records
    resolve6=$(f_RESOLVE_HOSTS6 "$temp/rdns_records")
    [[ -n "$resolve6" ]] && f_HEADLINE2 "IPV6 HOSTS\n" && echo -e "$resolve6\n"
  fi
fi
}

f_REV_IP(){
$CURL -s -m 30 "https://api.hackertarget.com/reverseiplookup/?q=$1${api_key_ht}" | sed 's/No DNS A records found/\nno_records\n/' > $temp/revip
f_HEADLINE2 "$1  REVERSE IP  (SOURCE: HACKERTARGET.COM)\n"
if [[ $(wc -l < $temp/revip) -lt 2 ]]; then
  echo -e "No results\n"
else
  echo '' | tee -a $temp/revip
  if [[ $(egrep -o -c '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $temp/revip) -gt 1 ]]; then
    awk -F ',' '{print $2",\t\t"$1}' $temp/revip | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n
  else
    if [[ $(wc -l < $temp/revip) -lt "1001" ]] ; then
      $DIG +noall +answer +noclass +nottlid -f $temp/revip | sed 's/A/,/' | sed '/NS/d' | sed '/CNAME/d' | tr -d ' ' | sed 's/,/  /g'
    else
      cat $temp/revip ; echo ''
    fi
  fi
fi
}

#-------------------------------  HOST DNS  -------------------------------

f_DNS_TRACE(){
f_HEADLINE2 "DNS DELEGATION\n\n"
grep ';; Received' $temp/dns_trace | grep 'from' | awk -F'from' '{print $2}' | sed 's/\#53/ \#53 /' |
sed 's/) in/)\n  -> /'
[[ $host_type = "hostname" ]] && result=$(grep -sw "${1}." $temp/dns_trace | grep -sEw "A|AAAA") || result=$(grep -sw "PTR" $temp/dns_trace)
[[ -n "$result" ]] && echo -e "\n\n$result\n"
echo -e "\nAUTH NS\n"
grep -sw "${1}." $temp/dns_trace | grep -sw "NS"; echo ''
}

f_DNS_DIAG(){
f_HEADLINE2 "$1  DNS LOOKUP   (Source: RIPEstst Data API, $file_date)\n"
$CURL -s -m 15 --location --request GET "https://stat.ripe.net/data/dns-chain/data.json?resource=$1" > $temp/dns.json
status_ok=$($JQ '.status?' $temp/dns.json | grep -sEoi "^ok")
[[ -n "$status_ok" ]] && host_ns=$(f_HOST_AUTHNS)
if [ -n "$host_ns" ]; then
  jq -r '.data.forward_nodes' $temp/dns.json | tr -d '{},"' | sed 's/\[/\n/g' | sed 's/\]//'
  echo -e "\nAUTH NS\n\n$host_ns\n"
fi
f_HEADLINE2 "FORWARD CONFIRMED RDNS  (Nameserver: System default)"
if [ $option_connect != "0" ]; then
  if [ $host_type = "ip" ]; then
    testPTR=$(/usr/bin/dig +short $1)
    if [ -n "$testPTR" ]; then
      $NMAP -Pn -sn -R --resolve-all --script=fcrdns $1 2>/dev/null > $temp/fcrdns
      echo ''; f_printFCRDNS
    else
      echo -e "\n$1 has no PTR record"
    fi
    /usr/bin/dig +noall +answer +noclass +trace +nodnssec -x $1 > $temp/dns_trace
    f_DNS_TRACE "$1"
  else
    testA=$(/usr/bin/dig +short $1); [[ -n "$testA" ]] && hasA=$(f_EXTRACT_IP4 "$testA")
    testAAAA=$(/usr/bin/dig aaaa +short $1); [[ -n "$testAAAA" ]] && hasAAAA=$(f_EXTRACT_IP6 "$testAAAA")
    if [ -n "$hasA" ]; then
      $NMAP -Pn -sn -R --resolve-all --script=fcrdns $1 2>/dev/null > $temp/fcrdns
      echo ''; f_printFCRDNS
    fi
    if [ -n "$hasAAAA" ]; then
      $NMAP -6 -Pn -sn -R --resolve-all --script=fcrdns $1 2>/dev/null > $temp/fcrdns
      echo ''; f_printFCRDNS
    fi
    if [ -n "$hasA" ]; then
      /usr/bin/dig -t a +noall +answer +noclass +trace +nodnssec $1 > $temp/dns_trace
      f_DNS_TRACE "$1"
    elif [ -n "$hasAAAA" ]; then
      /usr/bin/dig -t aaaa +noall +answer +noclass +trace +nodnssec $1 > $temp/dns_trace
      f_DNS_TRACE "$1"
    fi
  fi
fi
}

f_LOCAL_DNS(){
[[ $1 =~ $REGEX_IP6 ]] && opt_v6="-6" || opt_v6=""
$NMAP $opt_v6 --system-dns -R --resolve-all -Pn -sn -sL $1 2>/dev/null > $temp/local_dns
if [ -f $temp/local_dns ]; then
  if [[ $1 =~ $REGEX_IP46 ]]; then
    local_dns=$(grep 'Nmap scan report' $temp/local_dns | grep '(' | awk '{print $5,$6}' | tr -d '()' | awk '{print $2,"  -  ",$1}')
  else
    local_dns=$(grep 'Nmap scan report' $temp/local_dns | grep '(' | awk '{print $5,$6}' | tr -d '()' | awk '{print $1,"  -  ",$2}')
  fi
  other_addr=$(grep 'Other addresses' $temp/local_dns | awk -F'):' '{print $NF}' | sed 's/ /  /g' | sed 's/^ *//')
  echo "$local_dns  $other_addr"
fi
}

f_HOST_AUTHNS(){
[[ -f $temp/dns.json ]] && auth_ns=$($JQ '.data.authoritative_nameservers[]' $temp/dns.json | sort -V)
if [ -n "$auth_ns" ]; then
  f_TRIM "$auth_ns" | tr '[:space:]' ' ' | sed 's/ /  /g' | fmt -w 80; echo ''
fi
}

f_HOST_DNS(){
[[ -f $temp/dns.json ]] && rm $temp/dns.json; [[ -f $temp/host_ips ]] && rm $temp/host_ips
[[ -f $temp/rdns ]] && rm $temp/rdns; [[ -f $temp/host_ns ]] && rm $temp/host_ns
$CURL -s -m 15 --location --request GET "https://stat.ripe.net/data/dns-chain/data.json?resource=$1" > $temp/dns.json
status_ok=$($JQ '.status?' $temp/dns.json | grep -sEoi "^ok")
[[ -n "$status_ok" ]] && host_ns=$(f_HOST_AUTHNS)
if [ -n "$host_ns" ]; then
  [[ $1 =~ $REGEX_IP46 ]] && f_HOST_RDNS "$1" || f_HOSTNAME_DNS "$1"
else
  f_LOCAL_DNS "$1"
fi
}

f_HOSTNAME_DNS(){
host_ns=$(f_HOST_AUTHNS)
forward_nodes=$($JQ '.data.forward_nodes' $temp/dns.json | sed 's/\[\]/nnn null/' | tr -d '{}\"' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' |
tr '[:space:]' ' '  | sed 's/\[/\n___/g' | sed 's/\,/ /g' | sed 's/] /\n\n/g' | sed 's/___ / /' | sed 's/nnn/\n\n /' | sed '1s/$/\n/'; echo '')
echo -e "\n$forward_nodes" | tee -a $temp/host_dns
$JQ '.data.forward_nodes[] | flatten | .[]?' $temp/dns.json > $temp/host_ips
[[ $domain_enum = "true" ]] && f_EXTRACT_IP4 "$temp/host_ips" >> $temp/ips_all
if [ $target_type = "default" ] || [ $target_type = "hostname" ]; then
  [[ $domain_enum = "false" ]] && echo -e "\n\nAuth NS:\n\n$host_ns\n"
fi
if [ $target_type = "hostname" ]; then
  if [[ $(grep -Ec "$REGEX_IP4" $temp/host_ips) -gt 0 ]]; then
    f_Long; f_WHOIS_TABLE "$temp/host_ips"; f_EXTRACT_IP4 "$temp/host_ips" > $temp/tmp
    [[ -f $temp/tmp ]] || f_EXTRACT_IP6 "$temp/host_ips" > $temp/tmp
  fi
  if [ $lod = "1" ]; then
    echo ''
    for i in $(cat $temp/tmp); do
      $CURL -s -m 7 "http://ip-api.com/json/${i}?fields=16802837" > $temp/geo.json
      pfx_resp=$(f_getPFX "$i"); pfx_rir=$(echo "$pfx_resp" | cut -s -d '|' -f 4 | tr -d ' ')
      pfx_ctry=$(echo "$pfx_resp" | cut -s -d '|' -f 3 | tr -d ' '); pfx=$(echo "$pfx_resp" | cut -s -d '|' -f 2 | tr -d ' ')
      [[ -n "$pfx" ]] && print_pfx="$pfx | "
      abu=$($DIG +short $(f_REVERSE "$i").abuse-contacts.abusix.zone txt | tr -d '"' | grep '@' | sed 's/^[ \t]*//;s/[ \t]*$//')
      [[ -n "$abu" ]] && print_abu="$abu |"
      geo_country=$($JQ '.country' $temp/geo.json | sed 's/United States/US/' | sed 's/United Kingdom/UK/')
      loc=$($JQ '.city, .region' $temp/geo.json | tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//')
      hosting=$($JQ '.hosting' $temp/geo.json | sed 's/true/HOSTING |/' | sed '/false/d')
      echo -e "\n$i\n\n$loc, $geo_country | $print_abu $hosting ${print_pfx}$(f_toUPPER "$pfx_rir"), $pfx_ctry\n"
    done
  fi
fi
}

f_HOST_RDNS(){
f_HOST_AUTHNS > $temp/host_ns
reverse_nodes=$($JQ '.data.reverse_nodes[] | .[]' $temp/dns.json | sort -u)
if [[ $(f_countW "$reverse_nodes") -eq 1 ]]; then
  forward4=$(f_EXTRACT_IP4 "$($JQ '.data.forward_nodes[]? | .[]' $temp/dns.json | sort -u)" | tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//')
  forward6=$(f_EXTRACT_IP6 "$($JQ '.data.forward_nodes[]? | .[]' $temp/dns.json | sort -u)" | tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//')
  [[ $1 =~ $REGEX_IP4 ]] && [[ -n "$forward6" ]] && ip_alt="$forward6"
  [[ $1 =~ $REGEX_IP6 ]] && [[ -n "$forward4" ]] && ip_alt="$forward4"
  [[ -n "$ip_alt" ]] && echo "$reverse_nodes  ($ip_alt)" || echo "$reverse_nodes"
elif [[ $(f_countW "$reverse_nodes") -gt 1 ]]; then
  $JQ '.data.reverse_nodes' $temp/dns.json | sed '/}/d' | tr -d '{[],\"' > $temp/rdns
fi
}

f_printAUTH_NS(){
if [ $target_type != "net" ] && [ -f $temp/host_ns ]; then
  f_HEADLINE2 "AUTH NS\n"; cat $temp/host_ns
fi
if [ $rir = "lacnic" ]; then
  f_HEADLINE2 "AUTH NS  (SOURCE: WHOIS)\n"
  grep -E "^nserver:" $temp/whois | awk '{print $NF}' | tr -d ' ' | sort -uV | tr '[:space:]' ' ' | sed 's/ /  /g' |
  sed 's/^ *//' | fmt -w 80; echo ''
fi
}

f_RESOLVE_ALL(){
[[ -f $temp/resolve_tmp ]] && rm $temp/resolve_tmp
f_RESOLVE_v4 "$1" > $temp/resolve_tmp; f_RESOLVE_v6 "$1" >> $temp/resolve_tmp
[[ -f $temp/resolve_tmp ]] && cat $temp/resolve_tmp
}

f_RESOLVE_v4(){
$DIG a +short $1 | grep -sEo "$REGEX_IP4" | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n -u
}

f_RESOLVE_v6(){
$DIG aaaa +short $1 | grep -sEo "$REGEX_IP6" | sort -uV
}

f_RESOLVE_HOSTS4(){
[[ $target_type = "net" ]] && local to_resolve="$1" || local to_resolve="-iL $1"
$NMAP $to_resolve -sn -Pn -sL $nmap_ns 2>/dev/null | grep -sE "$REGEX_IP46" | grep '(' > $temp/resolved_tmp
if [ -f $temp/resolved_tmp ] && [[ $(grep -sEc "$IP4_ALT" $temp/resolved_tmp) -gt 0 ]]; then
  grep -sE "$IP4_ALT" $temp/resolved_tmp | sed 's/not scanned): //' | tr -d ')' | grep -sE "scan report|Other addresses" | rev |
  cut -d ' ' -f -2 | rev | sed 's/(/,/' | tr -d ' ' > $temp/resolved_tmp2
  if [ $target_type = "subdomain" ]; then
    cat $temp/resolved_tmp2 >> $temp/subs_tmp
  else
    sort -t ',' -k 1 $temp/resolved_tmp2 | sed 's/,/ => /' | awk '{print $3 "\t\t" $2 "\t" $1}' | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n
  fi
else
  [[ $domain_enum = "true" ]] || echo -e "No results\n"
fi
}

f_RESOLVE_HOSTS6(){
local hosts_file="$*"
host6_resolved=$($NMAP -6 -sn -Pn -sL -iL $hosts_file $nmap_ns 2>/dev/null | grep -sE "$REGEX_IP6" | grep 'report' | tr -d '()' |
awk '{print $6","$5}' | sort -t ',' -k 1 | sed 's/,/\n  ->  /' | sed '/./{x;p;x;}')
[[ -n "$host6_resolved" ]] && echo -e "\n$host6_resolved\n" || echo -e "No results\n"
}

f_VHOSTS(){
 [[ -f $temp/compromised ]] && rm $temp/compromised
$CURL -sL https://rapiddns.io/sameip/$1 | grep '<td>' | grep -v 'href=' | grep -soP '<td>\K.*?(?=</td>)' > $temp/revip_raw
[[ -f $temp/revip_raw ]] && vhosts=$(f_EXTRACT_HOSTN "$temp/revip_raw")
if [ -n "$vhosts" ]; then
  f_HEADLINE2 "REVERSE IP (rapiddns.io) - Hosts: $vhost_count\n\n" | tee $temp/vhosts_tmp
  for v in $vhosts; do
    [[ $(echo "$monero_pools" | grep -wic "$v") -gt 0 ]] && is_monero_pool="true" || is_monero_pool="false"
    [[ $threat_enum = "true" ]] && f_DOMAIN_REPUTATION "$v"
  done
  if [[ $vhost_count -lt 100 ]]; then
    echo -e "$print_vhosts"
  else
    echo -e "Output written to file"; cat $temp/vhosts_tmp > ${outdir}/VHOSTS_${filename}.txt
    echo -e  "$print_vhosts" >> ${outdir}/VHOSTS_${filename}.txt
  fi
fi
}

# -------------------------  FORWARD CONFIRMED REVERSE DNS  ---------------------------------

f_FCRDNS(){
echo ''; f_HEADLINE2 "FORWARD CONFIRMED REVERSE DNS"
if [ -f $temp/d4 ] || [ -f $temp/d6 ]; then
  echo -e "\n\nDOMAIN HOSTS"
  [[ -f $temp/d4 ]] && f_getFCRDNSv4 "$x"; [[ -f $temp/d6 ]] && f_getFCRDNSv6 "$x"; echo ''
fi
echo -e "\n\nNS RECORDS"
for n in $(sort -uV $temp/ns_servers); do
  [[ -f $temp/ns_servers4 ]] && [[ $(grep -c $n $temp/ns_servers4) -gt 0 ]] && f_getFCRDNSv4 "$n"
  [[ -f $temp/ns_servers6 ]] && [[ $(grep -c $n $temp/ns_servers6) -gt 0 ]] && f_getFCRDNSv6 "$n"
done; echo ''
if [ -f $temp/mx_hosts ]; then
  echo -e "\n\nMX RECORDS"
  for m in $(sort -uV $temp/mx_hosts); do
    [[ -f $temp/mx_servers4 ]] && [[ $(grep -c $m $temp/mx_servers4) -gt 0 ]] && f_getFCRDNSv4 "$m"
    [[ -f $temp/mx_servers6 ]] && [[ $(grep -c $m $temp/mx_servers6) -gt 0 ]] && f_getFCRDNSv6 "$m"
  done; echo ''
fi
}

f_getFCRDNSv4(){
$NMAP -Pn -sn -R --resolve-all --script=fcrdns ${nmap_ns} $1 2>/dev/null > $temp/fcrdns
[[ -f $temp/fcrdns ]] && [[ $(grep -c 'Host script results:' $temp/fcrdns) -gt 0 ]] && f_printFCRDNS && rm $temp/fcrdns
}

f_getFCRDNSv6(){
$NMAP -6 -Pn -sn -R --resolve-all --script=fcrdns ${nmap_ns} $1 2>/dev/null > $temp/fcrdns
[[ -f $temp/fcrdns ]] && [[ $(grep -c 'Host script results:' $temp/fcrdns) -gt 0 ]] && f_printFCRDNS && rm $temp/fcrdns
}

f_printFCRDNS(){
if [ -f $temp/fcrdns ] && [[ $(grep -c 'status:' $temp/fcrdns) -gt 3 ]]; then
  grep -sEa "scan report|^\|" $temp/fcrdns | sed 's/Nmap scan report for /\n/' | sed 's/fcrdns: //' | tr -d '|_' |
  sed 's/pass/PASS/' | sed 's/fail/FAIL/'
else
  print_fcrdns=$(grep -sEa "scan report|^\|" $temp/fcrdns |  sed '/|_/a ==' | tr -d '|_' | sed 's/status:/-/' |
  sed 's/addresses:/-/' | sed 's/reason:/-/' | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' |
  sed 's/Nmap scan report for /\n\n> /g' | sed 's/==/\n/g' | sed 's/nnn/\n\n/g' | sed 's/fcrdns:/\n\n/g' | sed 's/^ *//' |
  sed 's/: - pass/ - PASS/g' | sed 's/: - [Ff][Aa][Ii][Ll]/ - FAIL/' | sed 's/(No PTR record)/No_PTR/g' | sed 's/ /  /g' |
  sed 's/-  PASS  -/- PASS -/g' | sed 's/-  FAIL  -/- FAIL -/g' | sed 's/^/   /' | sed 's/^   > //' | sed 's/No_PTR/No PTR/g')
  fcrdns4=$(grep '|' $temp/fcrdns | grep -v ':' | grep -sEo "$IP4_ALT" | sort -u)
  fcrdns6=$(grep '|' $temp/fcrdns | grep -v 'fcrdns:' | grep -sEo "$REGEX_IP6" | sort -u)
  if [ -n "$fcrdns4" ]; then
    [[ $(f_countW "$fcrdns4") -gt 7 ]] && echo -e "$print_fcrdns" | fmt -s -w 60 || echo -e "$print_fcrdns" | fmt -s -w 80
  elif [ -n "$fcrdns6" ]; then
    [[ $(f_countW "$fcrdns6") -lt 3 ]] && echo -e "$print_fcrdns" | fmt -s -w 120 || echo -e "$print_fcrdns" | fmt -s -w 80
  else
    echo -e "$print_fcrdns" | fmt -s -w 80
  fi
fi
}

# --------------------------------  DOMAIN DNS RESOURCE RECORDS  -------------------------------------

f_AXFR(){
if [ $domain_enum = "true" ] || [ $option_dns != "1" ]; then
  echo ''; f_HEADLINE3 "[AXFR]  $1  ($file_date)"
else
  f_HEADLINE2 "ZONE TRANSFER\n"
fi
$CURL -s -m 20 https://api.hackertarget.com/zonetransfer/?q=${1}${api_key_ht} > $temp/zone.txt
f_EXTRACT_IP4 "$temp/zone.txt" >> $temp/ips.list; echo '' >> $temp/zone.txt; cat $temp/zone.txt
}

f_DNS_CAA(){
dns_caa=$($DIG +short caa $1 | grep -sEi "issue|issuewild")
if [ -n "$dns_caa" ]; then
  [[ $domain_enum = "false" ]] && echo ''; echo -e "\nDNS CAA\n\n$dns_caa"
else
  [[ $domain_enum = "true" ]] && echo -e "\nDNS CAA: No CAA record found" || echo -e "\n\nDNS CAA\n\nNo CAA record found"
fi
}

f_DNS_RR(){
[[ -f $temp/d4 ]] && rm $temp/d4; [[ -f $temp/d6 ]] && rm $temp/d6
f_HEADLINE3 "[DNS]  $x  -  $file_date"
cat $temp/whois_status && echo '' && f_Long
domain_ns=$(f_NS "$x")
if [ -f $temp/ns_servers ] && [[ $(wc -w < $temp/ns_servers) -gt 0 ]]; then
  echo -e "\nDOMAIN HOST\t\t$x\n\n"
  $DIG "${dig_array[@]}" "$x" | grep -w 'A' | tee $temp/hostsA.list | awk '{print $2"\t\t\t"$4}'
  $DIG aaaa "${dig_array[@]}" "$x" | grep -w 'AAAA' | tee $temp/hostsAAAA.list | awk '{print $2"\t\t\t"$4}'
  hostA=$(f_EXTRACT_IP4 "$temp/hostsA.list"); hostAAAA=$(f_EXTRACT_IP6 "$temp/hostsAAAA.list")
  [[ -n "$hostA" ]] && echo "$hostA" | tee -a $temp/dns4 > $temp/d4
  [[ -n "$hostAAAA" ]] && echo "$hostAAAA" | tee -a $temp/dns6 > $temp/d6
  f_MX "$x"; echo -e "$domain_ns"; f_SOA "$x"
  cat $temp/ns_ipv4.list | tee -a $temp/dns4 > $temp/ns1; [[ -f $temp/ns_ipv6.list ]] && cat $temp/ns_ipv6.list | tee -a $temp/dns6 >> $temp/ns1
  [[ $rfc1912 = "true" ]] && f_RFC1912 "$x"
  txt_rec=$($DIG +short txt $x); f_EXTRACT_IP4 "$txt_rec" > $temp/txt+srv
  f_EXTRACT_IP4_ALL "$txt_rec" | cut -d '/' -f 1 >> $temp/dns4.list
  [[ $option_connect = "0" ]] || srv_rec=$(f_SRV_REC "$x"); [[ -n "$srv_rec" ]] && echo -e "$srv_rec"
  [[ -n "$txt_rec" ]] && f_HEADLINE2 "TXT RECORDS\n" && echo "$txt_rec" | sed '/\"/{x;p;x;}' | fmt -s -w 90
  f_DNSSEC "$x"; f_DNS_CAA "$x"
  [[ $option_connect != "0" ]] && [[ -z "$srv_rec" ]] && echo -e "\n\nSRV\n\nNo SRV record found"
  echo ''; f_Long; f_WHOIS_TABLE "$temp/dns4" | sed '/ORG NAME/G'
  if [ $option_connect != "0" ] ; then
    f_VERSION_BIND
    f_HEADLINE2 "Checking name server response via SOA record query ...\n\n"
    $DIG +short +nssearch $x > $temp/nssearch
    serials=$(grep 'SOA' $temp/nssearch | awk '{print $4}' | tr -d ' ' | sort -u)
    if [[ $(f_countL "$serials") = 1 ]]; then
      echo -e "Zone serials match (ok): $serials\n"
      grep 'SOA' $temp/nssearch | awk '{print $11,$12,$13,$14}' | sed 's/in//' | sed 's/ ms./ms/' | awk '{print $2,"for",$1}'
    else
      echo -e "Zone serials don't match (not ok)\n\n"
      grep 'SOA' $temp/nssearch | awk '{print $2,$4,$9,$11,$12,$13,$14}' | sed 's/in/ ->/' | sed 's/ ms./ms/'
    fi
      f_EXTRACT_IP4 "$temp/nssearch" > $temp/ns2; f_EXTRACT_IP6 "$temp/nssearch" >> $temp/ns2
      ns_diff=$(comm -1 -3 $temp/ns1 $temp/ns2)
    if [ -n "$ns_diff" ]; then
      echo -e "\nTrying to ping non responding servers:\n\n$ns_diff\n"
      for nd in $nsdiff; do
        opt_v6""; [[ $nd =~ $REGEX_IP4 ]] || opt_v6="-6"
        $NPING $opt_v6 --safe-payloads --tcp-connect -p 53 -c 4 $nd > $temp/np; f_printNPING
      done
    fi
  fi
  [[ $option_axfr = "y" ]] && f_AXFR "$x"
  if [ -f $temp/mx_ipv4.list ]; then
    echo ''; f_Long; echo -e "\nChecking SPAM & IP blocklists for MX servers... \n"
    for mxa in $(cat $temp/mx_ipv4.list); do f_IP_REPUTATION2 "$mxa"; done
    [[ $option_connect != "0" ]] && [[ $mx_banners = "true" ]] && f_MX_BANNERS
    [[ $option_connect != "0" ]] && [[ $ssl_diag = "false" ]] && f_MX_SSL
  fi
  if [ $option_connect != "0" ]; then
    if [ -f $temp/d4 ] ||  [ -f $temp/d6 ]; then
      [[ $ssl_diag = "false" ]] && f_DOMAIN_HOST_SSL "$x"
    fi
    f_DOMAIN_HOSTS; [[ $send_ping = "true" ]] && f_PING_SRV
  fi
    f_FCRDNS; echo ''; f_TTL_ALT
  f_Long; echo -e "\nPREFIXES\n"; f_DNS_PREFIXES
else
  echo -e "\nERROR retrieving results\n"
fi
}

f_DNSSEC(){
delv @1.1.1.1 +noclass +nottl +multiline "$x" > $temp/is_signed
is_signed=$(grep -sEa "^;" $temp/is_signed | tr -d ';' | sed 's/^ *//')
f_HEADLINE2 "DNSSEC\n"
if echo "$is_signed" | grep -q -E "unsigned answer"; then
   echo "$is_signed"
else
  cat $temp/is_signed
  dns_key=$($DIG dnskey +noall +answer +noclass +nottlid "$x" | awk -F'DNSKEY' '{print "DNSKEY:" $NF}')
  [[ -n "$dns_key" ]] && echo -e "\n$dns_key"
  if echo "$is_signed" | grep -q -E "fully validated"; then
    nsec=$($DIG nsec +noall +answer +nottl +noclass "$x" | awk -F'NSEC' '{print "NSEC:",$NF}')
    nsec3=$($DIG +dnssec +noquestion +nocomments +noclass +nocmd +authority +multiline +nostats nsec3 "$x" |
    sed -n '/RRSIG/,$p' | sed 's/\\/\n\n/' | sed '/)/G' | sed '/(/{x;p;x;}')
    [[ -n "$nsec" ]] && echo -e "\nNSEC\n\n$nsec"; [[ -n "$nsec3" ]] && echo -e "\nNSEC3\n\n$nsec3"
  else
    echo -e "\nNo NSEC/NSEC3 records"
  fi
fi
}

f_DOMAIN_DNS(){
[[ -f $temp/dns4 ]] && rm $temp/dns4; [[ -f $temp/dns6 ]] && rm $temp/dns6
[[ -f $temp/mx_list ]] && rm $temp/mx_list; [[ -f $temp/mx_hosts ]] && rm $temp/mx_hosts
[[ -f $temp/m4 ]] && rm $temp/m4; [[ -f $temp/n4 ]] && rm $temp/n4
f_HEADLINE3 "[DNS RECORDS]   $1"; echo ''
f_toUPPER "$1"; echo ''
$DIG ${dig_array[@]} $1 > $temp/domainA; $DIG aaaa ${dig_array[@]} $1 > $temp/domainAAAA
[[ -f $temp/domainA ]] && [[ $(grep -c "CNAME" $temp/domainA) -gt 0 ]] && cat $temp/domainA && echo '' 
[[ -f $temp/domainA ]] && hostA=$(f_EXTRACT_IP4 "$(grep -w "$1" $temp/domainA)")
[[ -f $temp/domainAAAA ]] && hostAAAA=$(f_EXTRACT_IP6 "$(grep -w "$1" $temp/domainA)")
[[ -n "$hostAAAA" ]] && echo "$hostAAAA" >> $temp/dns6 && printAAAA=$(echo "$hostAAAA" | tr '[:space:]' ' ' | sed 's/ /  /g'; echo '')
if [ -n "$hostA" ]; then
  d4_count=$(f_countW "$hostA"); echo "$hostA" > $temp/d4
  printA=$(echo "$hostA" | tr '[:space:]' ' ' | sed 's/ /  /g'; echo '')
else
  d4_count=0
fi
[[ -n "$printA" ]] || [[ -n "$printAAAA" ]] && echo -e "$printA $printAAAA\n"
echo -e "\nNS\n"
ns_hosts=$($DIG ns +short $1 | awk '{print $NF}' | rev | cut -c 2- | rev | sort -V)
[[ -n "$ns_hosts" ]] && echo "$ns_hosts" >> $temp/ns_servers
 for ns in $ns_hosts; do
  ns4=$($DIG +short $ns | grep -sEo "$IP4_ALT" | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n -u | tr '[:space:]' ' ' | sed 's/ /  /g')
  f_EXTRACT_IP4 "$ns4" | tee -a $temp/n4 > $temp/ns4
  ns6=$($DIG +short aaaa $ns | grep -sEo "$REGEX_IP6" | sort -V | tr '[:space:]' ' ' | sed 's/ /  /g') 
  if [[ $(f_countW "$ns4") -gt 3 ]]; then
    print_ns4=$(sort -t . -k 1,1n -k 2,2n -k 3,3n -u $temp/ns4 | head -2 | cut -d '.' -f -3 | sed 's/$/.x/' | tr '[:space:]' ' ' | sed 's/ /  /g'; echo '')
  else
    print_ns4="$ns4"
  fi
  ns6_count=$(f_countW "$ns6"); ns4_count=$(f_countW "$print_ns4"); ns_count_total=$(($ns4_count+$ns6_count))
  if [[ $ns_count_total -gt 5 ]]; then
    echo -e "\n$ns\n\n  $print_ns4  $ns6" | fmt -w 80
  else
    echo -e "\n$ns\t$print_ns4 $ns6"
  fi
done
echo -e "\n\nSOA\n"; $DIG soa +short $1
$DIG mx +short $1 > $temp/mx_list
[[ -f $temp/mx_list ]] && mx_count=$(wc -l < $temp/mx_list)
[[ -f $temp/mx_list ]] && mx_hosts=$(f_EXTRACT_HOSTN "$temp/mx_list")
if [ -n "$mx_hosts" ]; then
echo "$mx_hosts" >> $temp/mx_hosts
echo -e "\n\nMX"
  for mx in $mx_hosts; do
    mx_prio=$(grep -w -m 1 "$mx" $temp/mx_list | awk '{print $1}')
    mx4=$($DIG +short $mx | grep -sEo "$IP4_ALT" | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n -u | tr '[:space:]' ' ' | sed 's/ /  /g')
    f_EXTRACT_IP4 "$mx4" | tee -a $temp/m4 > $temp/mx4
    mx6=$($DIG +short aaaa $mx | grep -sEo "$REGEX_IP6" | sort -V | tr '[:space:]' ' ' | sed 's/ /  /g')
    if [[ $(f_countW "$mx4") -gt 3 ]]; then
      print_mx4=$(sort -t . -k 1,1n -k 2,2n -k 3,3n -u $temp/mx4 | head -2 | cut -d '.' -f -3 | sed 's/$/.x/' | tr '[:space:]' ' ' | sed 's/ /  /g'; echo '')
    else
      print_mx4="$mx4"
    fi
    mx6_count=$(f_countW "$mx6"); mx4_count=$(f_countW "$print_mx4"); mx_count_total=$(($mx4_count+$mx6_count))
    if [[ $mx_count_total -gt 5 ]]; then
      echo -e "\n$mx_prio  $mx\n\n  $print_mx4  $mx6" | fmt -w 80
    else
      echo -e "\n$mx_prio  $mx\t$print_mx4 $mx6"
    fi
    [[ -f $temp/mx4 ]] && rm $temp/mx4
  done
fi
txt_rec=$($DIG +short txt $1 | fmt -s -w 90)
if [ -n "$txt_rec" ]; then
  f_EXTRACT_IP4 "$txt_rec" > $temp/t+s; f_EXTRACT_IP4_ALL "$txt_rec" | cut -d '/' -f 1 >> $temp/dns4
fi
[[ $option_connect = "0" ]] || srv_rec=$(f_SRV_REC "$x"); [[ -n "$srv_rec" ]] && echo -e "$srv_rec"
[[ -n "$srv_rec" ]] && f_EXTRACT_IP4 "$srv_rec" >> $temp/t+s
[[ -n "$txt_rec" ]] && echo -e "\n\nTXT\n\n$txt_rec"
[[ -f $temp/d4 ]] && cat $temp/d4 | tee -a $temp/ips_all >> $temp/dns4
[[ -f $temp/n4 ]] && cat $temp/n4 >> $temp/dns4
[[ -f $temp/m4 ]] && cat $temp/m4 >> $temp/dns4
[[ -f $temp/t+s ]] && cat $temp/t+s >> $temp/dns4
cat $temp/dns4 | tee -a $temp/dns_ips >> $temp/ips.list
[[ -f $temp/dns6 ]] && cat $temp/dns6 >> $temp/dns_ips
echo ''; f_Long; f_WHOIS_TABLE "$temp/dns4" | sed '/ORG NAME/G'
[[ $option_connect != "0" ]] && f_Long && f_DNS_CAA "$1" && f_VERSION_BIND
if [[ $mx_count -gt 0 ]]; then
  if [ $option_connect != "0" ]; then
    f_Long
    for mx in $(cat $temp/mx_hosts); do
      echo -e "\n+  $mx SMTP BANNER\n"
      smtp_banner=$($TOUT 5 $NCAT $mx 25 | grep -sE "^[2-5]{1}+[0-9]{2}*")
      [[ -n "$smtp_banner" ]] && echo "   $smtp_banner" || echo "   Failed to retrieve banner"; echo ''
      f_MX_SSL "$mx"
    done; f_Long
  fi
fi
}

f_getCNAME(){
$DIG cname +noall +answer $1 | grep CNAME | awk '{print $NF}' | grep -v CNAME | rev | cut -c 2- | rev
}

f_getHOST_A(){
$CURL -s -m 15 "https://dns.google/resolve?name=${1}&type=a&do=1" > $temp/targetA.json
hostA_result=$($JQ '.Answer[].data?' $temp/targetA.json | tr '[:space:]' ' ' | sed 's/ /  /g'; echo '')
[[ -n "$hostA_result" ]] && [[ $(f_countW "$hostA_result") -gt 0 ]] && echo "$hostA_result"
}

f_getHOST_A_FULL(){
hostA=$(f_getHOST_A "$1")
if [ -n "$hostA" ]; then
  jq -r '.Answer[] | {NAME: .name, TTL: .TTL, IP: .data}' $temp/targetA.json | tr -d '{",}' | sed 's/^[ \t]*//;s/[ \t]*$//' |
  sed '/^$/d' | tr '[:space:]' ' '  | sed 's/NAME: /\n\n/g'| sed 's/TTL:/\t/' | sed 's/IP:/\t/'; echo ''
fi
}

f_getHOST_AAAA_FULL(){
hostAAAA=$(f_getHOST_AAAA "$1")
if [ -n "$hostAAAA" ]; then
  jq -r '.Answer[] | {NAME: .name, TTL: .TTL, IP: .data}' $temp/targetAAAA.json | tr -d '{",}' | sed 's/^[ \t]*//;s/[ \t]*$//' |
  sed '/^$/d' | tr '[:space:]' ' '  | sed 's/NAME: /\n\n/g'| sed 's/TTL:/\t/' | sed 's/IP:/\t/'; echo ''
fi
}

f_getHOST_AAAA(){
$CURL -s -m 15 "https://dns.google/resolve?name=${1}&type=aaaa&do=1" > $temp/targetAAAA.json
hostAAAA_result=$($JQ '.Answer[].data?' $temp/targetAAAA.json | tr '[:space:]' ' ' | sed 's/ /  /g'; echo '')
[[ -n "$hostAAAA_result" ]] && [[ $(f_countW "$hostAAAA_result") -gt 0 ]] && echo "$hostAAAA_result"
}

f_GOOGLE_DNS(){
$CURL -s -m 15 "https://dns.google/resolve?name=${1}&type=soa&do=1" > $temp/soa.json
$CURL -s -m 15 "https://dns.google/resolve?name=${1}&type=mx&do=1" > $temp/mx.json
[[ -f $temp/mx.json ]] && mx_hosts=$($JQ '.Answer[].data?' $temp/mx.json)
[[ -n "$mx_hosts" ]] && mx_count=$(f_EXTRACT_HOSTN "$mx_hosts" | wc -w) || mx_count=0
if [[ $mx_count -gt 0 ]]; then
  resolve_mx=$($JQ '.Answer[].data?' $temp/mx.json | awk '{print $NF}')
  echo "$mx_hosts" > $temp/mx.list
  for m in $resolve_mx; do
    $CURL -s "https://dns.google/resolve?name=${m}&type=a&do=1" > $temp/mx4.json
    m4=$($JQ '.Answer[] | .data?'  $temp/mx4.json | tr '[:space:]' ' ' | sed 's/ /  /g'; echo '')
    print_host=$(grep -w "$m" $temp/mx.list)
    [[ $(f_countW "$m4") -gt 4 ]] && echo -e "$print_host\n\n$m4" ||  echo -e "$print_host\t$m4"
  done > $temp/mx_hosts4
fi
[[ -f $temp/soa.json ]] && soa=$($JQ '.Answer[].data?' $temp/soa.json | head -1)
if [ $threat_enum = "false" ]; then
  hostA=$(f_getHOST_A "$1"); hostAAAA=$(f_getHOST_AAAA "$1")
  echo -e "\nA\n"; [[ -n "$hostA" ]] && echo -e "$1\t\t$hostA" || echo -e "No A record found for $1"
  [[ -n "$hostAAAA" ]] && echo -e "\n\nAAAA\n\n$1\t\t$hostAAAA"
fi
echo -e "\n\nSOA\n"
soa_host=$(echo "$soa" | awk '{print $1}')
$CURL -s -m 15 "https://dns.google/resolve?name=${soa_host}&type=a&do=1" > $temp/soa_ip4.json
soa_ip4=$($JQ '.Answer[].data?' $temp/soa_ip4.json | head -1)
print_soa=$(echo "$soa" | awk '{print $1,$2}'); echo -e "$print_soa\t$soa_ip4"
f_EXTRACT_IP4 "$soa_ip4" | tee -a $temp/lookup2 >> $temp/lookup3
mx_hosts=$($JQ '.Answer[].data?' $temp/mx.json  | awk '{print $NF}')
echo -e "\n\nMX\n"
if [[ $mx_count -gt 0 ]] && [ -f $temp/mx_hosts4 ]; then
  f_EXTRACT_IP4 $temp/mx_hosts4 | tee -a $temp/lookup2 >> $temp/lookup3; cat $temp/mx_hosts4
else
  echo "No MX records found"
fi
[[ -f $temp/lookup2 ]] && echo '' && f_Long && f_WHOIS_TABLE "$temp/lookup2"
}

f_printHOSTNAMES(){
rr_hostnames=$(f_getHOSTNAMES); [[ -n "$rr_hostnames" ]] && echo -e "\n$1\n\n$rr_hostnames\n"
}

f_RECORD_DETAILS(){
[[ -f $temp/rr_hostnames ]] && rm $temp/rr_hostnames
echo ''; f_HEADLINE3 "[DNS]  RESOURCE RECORDS DETAILS"
domain_hosts4=$(f_EXTRACT_IP4 "$temp/ips_all")
mx_hosts4=$(f_EXTRACT_IP4 "$temp/mx_ipv4.list")
ns_hosts4=$(f_EXTRACT_IP4 "$temp/ns_ipv4.list")
if [ -n "$domain_hosts4" ]; then
  echo -e "\nDOMAIN HOST"
  for a in $domain_hosts4; do
    echo ''; f_HOST_SHORT "$a"
    f_printHOSTNAMES "$a" | tee -a $temp/hostsnames_dns_records >> $temp/rr_hostnames
  done; echo ''; f_Long
fi
if [ -n "$mx_hosts4" ]; then
  echo -e "\nMX RECORDS"
  for m in $mx_hosts4; do
    echo ''; f_HOST_SHORT "$m"; f_printHOSTNAMES "$m" >> $temp/rr_hostnames
  done; echo ''; f_Long
fi
echo -e "\nNS RECORDS"
for n in $ns_hosts4; do
  echo ''; f_HOST_SHORT "$n"; f_printHOSTNAMES "$n" >> $temp/rr_hostnames
done
if [ -f $temp/txt+srv ]; then
  f_HEADLINE2 "TXT / SRV RECORDS\n"
  for a in $(cat $temp/txt+srv); do f_HOST_SHORT "$a"; echo ''
  f_printHOSTNAMES "$a" | tee -a $temp/hostsnames_dns_records >> $temp/rr_hostnames; done
  rm $temp/txt+srv
fi
if [ -f $temp/rr_hostnames ]; then
  echo ''; f_HEADLINE "DNS RECORDS HOSTNAMES"; echo ''; cat $temp/rr_hostnames
fi
}

f_RFC1912(){
local s="$*"; soa_rec=$($DIG soa +short $s); soa_host=$(echo "$soa_rec" | cut -d ' ' -f 1); f_HEADLINE2 "RFC 1912 CHECK\n\n"
$NMAP -sn -Pn ${soa_host} --script dns-check-zone --script-args=dns-check-zone.domain=$s 2>/dev/null | grep '|' |
tr -d '|_' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/dns-check-zone:/d' | sed '/DNS check results for domain:/d' | sed 's/^ *//' |
sed 's/^MX$/* MX/' | sed 's/^NS$/* NS/' | sed 's/^SOA$/* SOA/' | tr '[:space:]' ' ' | sed 's/* NS/\n\n* NS\n/' | sed 's/* MX/\n\n* MX\n/' |
sed 's/* SOA/\n\n* SOA\n/' | sed 's/PASS/\nPASS/g' | sed 's/FAIL/\nFAIL/g' | sed 's/SOA REFRESH //' | sed 's/SOA RETRY //' |
sed 's/SOA EXPIRE //' | sed 's/SOA MNAME entry check //' | sed 's/Recursive queries //' | sed 's/was within/within/' |
sed 's/Multiple name servers Server has/Multiple NS -/' | sed 's/DNS name server IPs are public/NS IPs -/' | sed 's/was NOT/ NOT /' |
sed 's/None of the servers allow recursive queries./Recursive queries not allowed/' | sed 's/Reverse MX A records //' |
sed 's/Missing nameservers reported by your nameservers /Missing NS reported by your NS - /' | sed 's/DNS server response //' |
sed 's/Missing nameservers/Missing NS/' | sed 's/parent/parent -/'  | sed 's/Zone serial numbers //' | sed '/./,$!d'; echo ''
}

f_TTL_ALT(){
dom_v4_ttlu=$($DIG ${nssrv_dig} +noall +answer +ttlunits $x); dom_v6_ttlu=$($DIG ${nssrv_dig} aaaa +noall +answer +ttlunits $x)
mx_ttlu=$($DIG ${nssrv_dig} mx +noall +answer +ttlunits $x); f_HEADLINE2 "TTL - HUMAN READABLE\n"
[[ -n "$dom_v4_ttlu" ]] && echo -e "\n$dom_v4_ttlu"; [[ -n "$dom_v6_ttlu" ]] && echo -e "\n$dom_v6_ttlu"
[[ -n "$mx_ttlu" ]] && echo -e "\n$mx_ttlu"; echo ''; $DIG ${nssrv_dig} ns +noall +answer +ttlunits $x; echo ''
}

# --------------------------------   DOMAIN HOSTS  -------------------------------------

f_DOMAIN_HOSTS(){
if [ $webpresence = "true" ]; then
  f_getWEB_IPS; f_HEADLINE2 "DOMAIN WEBPRESENCE\n"; f_printSTATUS; [[ $send_ping = "true" ]] && echo ''
else
  [[ -f $temp/x_ips ]] && cat $temp/x_ips > $temp/ips_all && f_HEADLINE2 "DOMAIN HOSTS PING"
fi
if [ -f $temp/ips_all ] && [ $send_ping = "true" ]; then
   [[ $webpresence = "true" ]] && echo -e "PING\n"
  for web_ip in $(f_EXTRACT_IP_ALL "$temp/x_ips"); do echo -e "\n$web_ip "; f_PING "$web_ip"; echo ''; done
fi
}

f_DOMAIN_HOST_SSL(){
echo | timeout 3 openssl s_client -connect $1:443 -verify_hostname $1 -brief 2>$temp/brief
verify_error=$(f_VALUE "=" "$(grep 'verify error:num' $temp/brief)")
[[ -n "$verify_error" ]] && self_signed=$(echo "$verify_error" | grep -o '18')
if [ -z "$verify_error" ] || [ -n "$self_signed" ]; then
  echo | timeout 3 openssl s_client -connect $1:443 2>$temp/x509 | $OPENSSL x509 >> $temp/x509
  [[ -f $temp/x509 ]] && $OPENSSL x509 -in $temp/x509 -outform PEM -out $temp/leaf.pem
  [[ -f $temp/leaf.pem ]] && f_SSL_SHORT "$1"
fi
}

# --------------------------------   MX RECORDS  -------------------------------------

f_MX(){
$DIG mx "${dig_array[@]}" "$1" | rev | cut -c 2- | rev > $temp/mx.list
if [ -f $temp/mx.list ] && [[ $(wc -w < $temp/mx.list) -gt 2 ]]; then
  f_EXTRACT_HOSTN "$temp/mx.list" >> $temp/hostsnames_dns_records
  mxs=$(awk '{print $NF}' $temp/mx.list)
  awk '{print $4,$5}' $temp/mx.list | tr [:upper:] [:lower:] | sort -t ' ' -k 1 | awk '{print $NF}' >> $temp/mx_hosts
  for mx in $mxs; do f_getCNAME "$mx"; done > $temp/mx_cnames
  [[ -f $temp/mx_cnames ]] && [[ $(wc -w < $temp/mx_cnames) -gt 0 ]] && mx_cnames="true" || mx_cnames="false"
  f_HEADLINE2 "MX SERVERS"
  if [ $mx_cnames = "false" ]; then
    for mx in $mxs; do
      echo -e "\n"; grep -w -m 1 "$mx" $temp/mx.list | awk '{print $2"\t\t\t"$4,$5}'; echo ''
      $DIG a "${dig_array[@]}" "$mx" | grep -w 'A' | tee -a $temp/mx4.list | awk '{print $2"\t\t\t"$4}'
      $DIG aaaa "${dig_array[@]}" "$mx" | grep -w 'AAAA' | tee -a $temp/mx6.list | awk '{print $2"\t\t\t"$4}'
    done
    if [ -f $temp/mx4.list ]; then
      grep -sEo "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" $temp/mx4.list |
      sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n -u | tee -a $temp/dns4 >> $temp/mx_ipv4.list
      awk '{print $1}' $temp/mx4.list | rev | cut -c 2- | rev >> $temp/mx_servers4; rm $temp/mx4.list
    fi
    if [ -f $temp/mx6.list ]; then
      awk '{print $NF}' $temp/mx6.list | tee $temp/mx_ipv6.list >> $temp/dns6
      awk '{print $1}' $temp/mx6.list | rev | cut -c 2- | rev >> $temp/mx_servers6; rm $temp/mx6.list
    fi
    echo -e "\n\nAliases:\t\tNo MX CNAME records found (OK)"
  else
    echo -e "\n\nAliases:\t\tMX CNAME records found (NOT OK)\n\n"; cat $temp/mx.list
    for mx in $mxs; do echo ''; $DIG a "${dig_array[@]}" "$mx"; $DIG aaaa "${dig_array[@]}" "$mx"; done | tee $temp/mxtmp
    if [ -f $temp/mxtmp ]; then
      f_EXTRACT_IP4 "$(grep 'A' $temp/mxtmp)" | tee -a $temp/dns4 > $temp/mx_ipv4.list
      f_EXTRACT_IP6 "$temp/mxtmp" | tee -a $temp/dns4 > $temp/mx_ipv6.list; rm $temp/mxtmp
    fi
  fi
else
  echo -e "\nNo MX records found"
fi
}

f_MX_BANNERS(){
if [ -f $temp/mx_hosts ]; then
  f_HEADLINE2 "MX RECORDS SMTP BANNERS"
  for m in $(cat $temp/mx_hosts); do
    for mxip in $(f_RESOLVE_ALL "$m"); do
      echo -e "\n\n$m  $mxip\n "
      [[ $mxip =~ $REGEX_IP6 ]] && opt_v6="-6" || opt_v6=""
      smtp_banner=$($TOUT 5 $NCAT $opt_v6 $mxip 25 | grep -sE "^[2-5]{1}+[0-9]{2}*")
      if [ -n "$smtp_banner" ]; then
        echo "$smtp_banner"
        imap_banner=$($TOUT 5 $NCAT $opt_v6 $mxip 143 | grep -sE "^[2-5]{1}+[0-9]{2}*")
        [[ -n "$imap_banner" ]] && echo "$imap_banner"
      else
        echo -e "No response, trying ping instead\n"
        if [ -n "$NPING" ]; then
          $NPING $opt_v6 --safe-payloads --tcp-connect -p 25 -c 4 $mxip > $temp/np; f_printNPING
        else
          f_PING "$mxip"
        fi
      fi
    done
  done
fi
}

f_MX_SSL(){
stls_port=""; [[ -f $temp/brief ]] && rm $temp/brief
f_HEADLINE2 "MX SSL\n"
for m in $(sort -uV $temp/mx_hosts); do
f_RESOLVE_ALL "$m" | head -12 > $temp/ssl_ips; mxa=$(head -1 $temp/ssl_ips)
echo | $TOUT 20 $OPENSSL s_client -starttls smtp -connect $m:25 -servername $m -verify_hostname $m -brief 2>$temp/brief
if [[ $(grep -c "Verification:" $temp/brief) -eq 1 ]]; then
  stls_port=25
else
  echo | $TOUT 20 $OPENSSL s_client -starttls smtp -connect $m:587 -servername $m -verify_hostname $m -brief 2>$temp/brief
  [[ $(grep -c "Verification:" $temp/brief) -eq 1 ]] && stls_port=587
fi
if [[ $(grep -c "Verification:" $temp/brief) -eq 0 ]]; then
  echo | $TOUT 20 $OPENSSL s_client -starttls smtp -connect ${mxa}:25 -servername $m -verify_hostname $m -brief 2>$temp/brief
  stls_port=25
  if [[ $(grep -oc "wrong version number" $temp/brief) -eq 1 ]]; then
    echo | $TOUT 20 $OPENSSL s_client -starttls smtp -connect ${mxa}:587 -servername $m -verify_hostname $m -brief 2>$temp/brief
    stls_port=587
  fi
 cat $temp/brief
  export stls_port; export stls_pro="smtp"
  verify_error=$(f_VALUE "=" "$(grep 'verify error:num' $temp/brief)")
  [[ -n "$verify_error" ]] && self_signed=$(echo "$verify_error" | grep -o '18')
fi
  if [ -z "$verify_error" ] || [ -n "$self_signed" ] || [[ $(grep -oc "Verification" $temp/brief) -eq 1 ]]; then
    echo | timeout 3 openssl s_client -starttls smtp -connect ${m}:${stls_port} 2>$temp/x509 | $OPENSSL x509 -text >> $temp/x509
    if [[ $(grep -oc "BEGIN" $temp/x509) -eq 0 ]]; then
      echo | timeout 3 openssl s_client -starttls smtp -connect ${mxa}:${stls_port} -servername $m 2>$temp/x509 | $OPENSSL x509 -text >> $temp/x509
    fi
    [[ -f $temp/x509 ]] && $OPENSSL x509 -in $temp/x509 -outform PEM -out $temp/leaf.pem
    [[ -f $temp/leaf.pem ]] && f_SSL_SHORT "$m"
    if [[ $(wc -w < $temp/ssl_ips) -gt 1 ]]; then
      for i in $(cat $temp/ssl_ips); do
        echo | timeout 3 $OPENSSL s_client -starttls smtp -connect [$i]:$stls_port -servername $m 2>/dev/null |
        $OPENSSL x509 -nocert -nameopt multiline -subject -fingerprint -sha256 | sed '/subject=/{x;p;x;}' > $temp/sha256
        c_name=$(sed -e '/./{H;$!d;}' -e 'x;/subject=/!d'  $temp/sha256 | grep -i 'commonName' | cut -d '=' -f 2- | sed 's/^ *//')
        echo "$i | $c_name | $cert_sha"
      done > $temp/sha256_compare
      sha_diff=$(sort -t '|' -k 3 -u $temp/sha256_compare)
      if [[ $(f_countL "$sha_diff" ) -gt 1 ]]; then
        echo -e "\n  DIFFERENT SHA256 FINGERPRINTS FOUND FOR HOST CERTIFICATES:\n"
        sed '/|/G' $temp/sha256_compare
      fi
    fi
  fi
done
}

# --------------------------------   NS RECORDS  -------------------------------------

f_NS(){
$DIG ns "${dig_array[@]}" "$x" | rev | cut -c 2- | rev > $temp/ns.list
awk '{print $NF}' $temp/ns.list > $temp/ns_servers
f_EXTRACT_HOSTN "$temp/ns_servers" >> $temp/hostsnames_dns_records
for ns in $(cat $temp/ns_servers); do f_getCNAME "$ns"; done > $temp/ns_cnames
[[ -f $temp/ns_cnames ]] && [[ $(wc -w < $temp/ns_cnames) -gt 0 ]] && ns_cnames="true" || ns_cnames="false"
f_HEADLINE2 "NS SERVERS"
if [ $ns_cnames = "false" ]; then
  for ns in $(cat $temp/ns_servers); do
    echo -e "\n"; grep -w "$ns" $temp/ns.list | awk '{print $2"\t\t\t"$4}'; echo ''
    $DIG "${dig_array[@]}" "$ns" | grep -w 'A' | tee -a $temp/ns4.list | awk '{print $2"\t\t\t"$4}'
    $DIG aaaa "${dig_array[@]}" "$ns" | grep -w 'AAAA' | tee -a $temp/ns6.list | awk '{print $2"\t\t\t"$4}'
  done
  if [ -f $temp/ns4.list ]; then
    f_EXTRACT_IP4 "$temp/ns4.list" | tee $temp/ns_ipv4.list >> $temp/dns4
    awk '{print $1}' $temp/ns4.list | rev | cut -c 2- | rev >> $temp/ns_servers4
  fi
  if [ -f $temp/ns6.list ]; then
    f_EXTRACT_IP6 "$temp/ns6.list" | tee $temp/ns_ipv6.list >> $temp/dns6
    awk '{print $1}' $temp/ns6.list | rev | cut -c 2- | rev >> $temp/ns_servers6; rm $temp/ns6.list
  fi
  echo -e "\n\nAliases:\t\tNo NS CNAME records found (OK)"
else
  echo -e "\n\nAliases:\t\tNS CNAME records found (NOT OK)\n\n"; cat $temp/ns.list
  for ns in $(cat $temp/ns_servers); do
    echo ''; $DIG a "${dig_array[@]}" "$ns"; $DIG aaaa "${dig_array[@]}" "$ns"
  done | tee $temp/nstmp
  if [ -f $temp/nstmp ]; then
    f_EXTRACT_IP4 "$(grep 'A' $temp/nstmp)" | tee -a $temp/dns4 > $temp/ns_ipv4.list
    f_EXTRACT_IP6 "$temp/nstmp" | tee -a $temp/dns6 > $temp/ns_ipv6.list; rm $temp/nstmp
  fi
fi
}

f_SOA(){
f_HEADLINE2 "START OF AUTHORITY\n\n"; $DIG soa +noall +answer +multiline $x > $temp/soa.txt
$DIG soa +noall +answer +noclass +ttlid $x | awk '{print $2,$3,$4,$5}' | sed 's/ /\t/g' ; echo ''
grep -E "; serial|; refresh|; retry|; expire|; minimum" $temp/soa.txt | awk '{print $3":",$1,$4,$5,$6,$7}' | sed 's/:/: /g' |
sed 's/serial:/serial: /' | sed 's/retry:/retry:  /' | sed 's/expire:/expire: /' | sed '/serial:/{x;p;x;G}'
}

f_VERSION_BIND(){
vers_bind=''; vers_bind_fail=''
if [ $option_connect != "0" ]; then
  [[ $domain_enum = "true" ]] && echo -e "\nVERSION.BIND\n" || f_HEADLINE2 "VERSION.BIND\n"
  for n in $(cat $temp/ns_servers); do
    bind_query=$($TOUT 7 /usr/bin/dig @${n} -r version.bind txt chaos +norecurse +noedns +short | tr -d '"' | sed 's/^ *//' |
    sed 's/;; connection timed out; no servers could be reached/timeout/g' | grep -E -v "^;|^;;" | sed '/^$/d')
    if [[ $(f_countW "$vers_bind_query") -eq 0 ]]; then
      vers_bind_fail="NA"
    elif [[ "$vers_bind_query" = "timeout" ]]; then
      vers_bind_fail="timeout"
    else
      vers_bind="$vers_bind_query"
    fi
    if [ -n "$vers_bind_fail" ]; then
      [[ $domain_enum = "true" ]] && echo -e "$n: $vers_bind_fail" || echo -e "\n$n: $vers_bind_fail"
    else
      echo -e "\n$n\n\n  vers.bind: $vers_bind"
    fi
  done
fi
}

# --------------------------------   SRV RECORDS  -------------------------------------

f_SRV_REC(){
srv_records=""
if [ $option_connect != "0" ] ; then
  srv_records=$($NMAP -Pn -sn --script dns-srv-enum --script-args dns-srv-enum.domain=$x 2>/dev/null | grep '|' |
  sed '/dns-srv-enum/d' | sed '/Active Directory/{x;p;p;x;}' | sed '/APT/{x;p;p;x;}' | sed '/Autodiscover/{x;p;p;x;}' |
  sed '/Kerberos/{x;p;p;x;}' | sed '/LDAP/{x;p;p;x;}' | sed '/Matrix/{x;p;p;x;}' | sed '/Minecraft/{x;p;p;x;}' |
  sed '/Mumble/{x;p;p;x;}' | sed '/SIP/{x;p;p;x;}' | sed '/SMTP/{x;p;p;x;}' | sed '/POP/{x;p;p;x;}' | sed '/IMAP/{x;p;p;x;}' |
  sed '/TeamSpeak/{x;p;p;x;}' | sed '/XMPP/{x;p;p;x;}' | sed '/prio/{x;p;x;}' | tr -d '|_' | sed 's/^ *//')
  if [ -n "$srv_records" ]; then
    echo "$srv_records" | grep -sE "^[0-9]{2,5}+/+tcp" | sed 's/\/tcp/;/' | awk '{print $1 $NF}' | sort -u | grep ';' > $temp/services
    srv_hosts=$(echo "$srv_records" | grep -sE ".*./tcp|.*./udp" | awk '{print $NF}' | sort -u)
    for h in $srv_hosts; do $DIG "${dig_array[@]}" "$h"; done > $temp/srv
    f_HEADLINE2 "SRV RECORDS"; echo "$srv_records"; echo -e "__________\n"
    if [ -f $temp/srv ]; then
      cat $temp/srv; f_EXTRACT_IP4 "$temp/srv" | tee -a $temp/txt+srv >> $temp/dns4; rm $temp/srv
    fi
  fi
fi
}

f_PING_SRV(){
if [ -f $temp/services ]; then
  f_HEADLINE2 "SRV RECORDS PING"
  for s_host in $(cut -s -d ';' -f 2 $temp/services | tr -d ' ' | sort -uV); do
    for s_a in $(f_RESOLVE_v4 "$s_host"); do echo -e "\n\n$s_host ($s_a)\n"; f_PING "$s_a"; done
    for s_z in $(f_RESOLVE_v6 "$s_host"); do echo -e "$\n\n$s_host ($s_z)\n"; f_PING "$s_z"; done
  done
  for srv in $(cat $temp/services); do
    srv_host=$(echo "$srv" | cut -s -d ';' -f 2 | tr -d ' '); dst_port=$(echo "$srv" | cut -s -d ';' -f 1 | tr -d ' ')
    for sa in $(f_RESOLVE_v4 "$srv_host"); do
      echo -e "\n\n$srv_host  ($sa) tcp/$dst_port\n"
      $NPING --safe-payloads --tcp-connect -p $dst_port -c 5 $sa > $temp/np; f_printNPING
    done
    for sz in $(f_RESOLVE_v6 "$srv_host"); do
      echo -e "\n\n$srv_host  ($sz) tcp/$dst_port\n"
      $NPING -6 --safe-payloads --tcp-connect -p $dst_port -c 5 $sz > $temp/np; f_printNPING
    done
  done; echo ''
fi
}

# ---------------------------------  WEB: CURL  -----------------------------------------

f_CURL_WRITEOUT(){
$DATE -R > $temp/tstamp
curl -m 20 -sLkv --trace-time ${curl_ua} $1 2>$temp/curl -D $temp/headers -o $temp/page_tmp -w \
"URL: %{url_effective}
HTTP/%{http_version} %{response_code}  |  Redirs: %{num_redirects}  TimeRE %{time_redirect} s  |  TOTAL: %{time_total} s
%{remote_ip}" > $temp/writeout; sed 's/TimeRE/->/' $temp/writeout > $temp/curlw
cat $temp/headers | tr [:upper:] [:lower:] | tee $temp/http > $temp/h3
grep -E ">|<|\*" $temp/curl | sed 's/*/   /' | sed 's/>/ > /' | sed 's/</ < /' > $temp/curl_verbose
sed 's/^[ \t]*//;s/[ \t]*$//' $temp/curl | cut -d ' ' -f 3- | sed 's/^ *//' | tee $temp/verb > $temp/curl_trimmed
f_EXTRACT_IP4 "$(grep -E "Connected to" $temp/curl_trimmed)" | tee -a $temp/ips_all >> $temp/ip4.list
f_EXTRACT_IP6 "$(grep -E "Connected to" $temp/curl_trimmed)" | tee -a $temp/ips_all >> $temp/ip6.list
f_HEADERS "$1" > ${outdir}/HTTP_HEADERS.$1.txt
if [ -f $temp/page_tmp ]; then
  sed 's/^[ \t]*//;s/[ \t]*$//' $temp/page_tmp | sed '/^$/d' | tr "'" '"' | sed 's/= /=/g' | sed 's/ =/=/g' | tr '[:space:]' ' ' |
  sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/<title/\n\n<title/g' | sed 's/<\/title>/<\/title>\n\n/g' | sed 's/<meta/\n\n<meta/g' |
  sed 's/<script/\n\n<script/g' | sed 's/<\/script>/<\/script>\n\n/g' | sed 's/<link/\n\n<link/g' |
  sed 's/<div/\n\n<div/g' | sed 's/<p/\n\n<p/g' | sed 's/<main/\n\n<main/g' | sed 's/<nav/\n\n<nav/g' |
  sed 's/<aside/\n\n<aside/g' | sed 's/<footer/\n\n<footer/g' > $temp/page
  grep -sioP '<link\K.*?(?=>)' $temp/page | grep -sEoi "https?://[^\"\\'> ]+" | tee $temp/cms_source > $temp/page_links
  grep -sioP '(<script).*?(?=<\/script>)' $temp/page | tee -a $temp/cms_source > $temp/page_scripts
  grep -sioP '(<meta).*?(?=>)'  $temp/page | tee -a $temp/cms_source > $temp/metas
  grep -sioP '(src=").*?(?=")' $temp/page | awk -F'src=' '{print $2}' | tr -d '"' | tr -d ' ' | tee -a $temp/cms_source > $temp/site_src
  [[ -f $temp/page_links ]] && cat $temp/page_links >> $temp/site_src
  grep -sEai -v "^location:" $temp/headers >> $temp/cms_src
fi
}

f_checkREDIRECTS(){
if [ -f $temp/ww ]; then
  remote_url=$(grep -soP 'Meta-Refresh-Redirect\[\K.*?(?=\])' $temp/ww)
else
  remote_url=$(grep -sEi "<meta http-equiv=(\")?refresh" $temp/page_tmp  | sed 's/= /=/g' | awk -F'[Uu][Rr][Ll]=' '{print $NF}' |
  grep -oaEi "https?://[^\"\\'> ]+")
fi
[[ -n "$remote_url" ]] && f_STRIP_URL "$remote_url"
}

f_getWEBHOST(){
http_refresh=$(f_checkREDIRECTS); [[ -n "$http_refresh" ]] && echo "$http_refresh" || f_STRIP_URL "$(f_printURL)"
}

f_getWEB_INFO(){
if [ $webpresence = "true" ]; then
  [[ $ww = "true" ]] && f_getWHATWEB "$x"
  meta_refresh=$(f_checkREDIRECTS)
  [[ -n "$meta_refresh" ]] && f_CURL_WRITEOUT "$meta_refresh"
  webhost=$(f_printWEBHOST); f_getWEB_IPS; f_detectCDN; imperva=$(f_IMPERVA)
  cat $temp/page_tmp > ${outdir}/SOURCE_${webhost}.html
  [[ $domain_enum = "true" ]] && x_dom="$x" || x_dom=$(f_EXTRACT_HOSTN "$temp/hostW_domain")
  [[ "$webhost" != "$x" ]] && web_dom=$(f_checkDOMAIN "$webhost") || web_dom="$x_dom"
  if [ $target_type = "web" ]; then
    web_ssl=$(f_WEBHOST_SSL)
    echo -e "\nWeb connect:     Success" >> ${out}
    echo -e "\nWebsite URL:     $(f_printURL)"
    echo -e "\nWebsite SSL:     $web_ssl"
  else
    web_status=$(grep 'TOTAL:' $temp/curlw | cut -d '|' -f 1 | sed 's/^[ \t]*//;s/[ \t]*$//')
    remote_ip=$(grep -m 1 -sEo "$REGEX_IP46" $temp/curlw)
    echo -e "\nWebsite:     $(f_printURL)"
    echo -e "\nStatus:      $web_status -> $remote_ip"
    if [ $webdata = "false" ]; then
      srv_header=$(grep -sEi "^server:" $temp/headers | cut -d ':' -f 2- | tail -1 | sed 's/^[ \t]*//;s/[ \t]*$//')
      echo -e "Title:        $(f_getTITLE "$temp/page")"
      [[ -n "$srv_header" ]] && echo -e "\nServer:     $srv_header"
    fi
  fi
  [[ $target_type = "web" ]] && f_WHOIS_STATUS "$x" || echo ''
  [[ "$webhost" != "$x" ]] && web_dom=$(f_checkDOMAIN "$webhost") || web_dom="$x_dom"
  [[ "$web_dom" != "$x_dom" ]] && f_WHOIS_STATUS "$web_dom" > $temp/webdom_whois
  [[ -f $temp/webdom_whois ]] && cat $temp/webdom_whois
  f_Long; f_HOST_DNS "$x"; [[ "$webhost" != "$x" ]] && f_HOST_DNS "$webhost"; echo ''
  if [ $target_type = "web" ] && [ -f $temp/web4 ]; then
    f_Long; f_WHOIS_TABLE "$temp/ips_all"; [[ -f $temp/as_table ]] && cat $temp/as_table
  fi
  f_getTXTS; f_handshakeHEADER "$webhost" > $temp/hndshake
  [[ $(wc -w < $temp/web_ips) -eq 1 ]] && f_printHANDSHAKE "$webhost"
fi
}

f_getWEB_IPS(){
f_RESOLVE_ALL "$x" | tee "${temp}/${x}_ips" | tee $temp/ips_all > $temp/x_ips
webhost=$(f_getWEBHOST)
[[ "$webhost" = "$x" ]] && cat $temp/x_ips > $temp/web_ips || f_RESOLVE_ALL "$webhost" | tee "${temp}/${webhost}_ips" > $temp/web_ips
if [ -f $temp/web_ips ]; then
  f_EXTRACT_IP4 "$temp/web_ips" > $temp/web4; f_EXTRACT_IP6 "$temp/web_ips" > $temp/web6; cat $temp/web_ips >> $temp/ips_all
fi
}

f_printSTATUS(){
[[ -f $temp/redir_ips ]] && rm $temp/redir_ips
grep -sE "URL|\|" $temp/curlw | tail -2 | sed '/HTTP/{x;p;x;G}' | sed '/URL:/{x;p;x;}' | sed 's/^URL://' | sed 's/^ *//' | sed 's/^/ /'
redir_ips=$(grep 'Connected to' $temp/curl_verbose | tr -d '()' | grep -sEo "$REGEX_IP46")
count_ips=$(f_countW "$(echo "$redir_ips" | sort -u)"); proxy=$(f_PROXY)
remote_ip=$(grep -m 1 -sEo "$REGEX_IP46" $temp/curlw)
if [[ $count_ips -gt 1 ]]; then
  echo "$redir_ips" > $temp/redir_ips
  print_redirs=$(sed 's/^/>/' $temp/redir_ips | tr '[:space:]' ' ' | tr -d ' ' | sed 's/^>//' | sed 's/>/  >  /g' ; echo '')
  [[ -n "$proxy" ]] && echo -e " -> $proxy\n"
  echo -e "  -> $print_redirs"
else
  print_redirs=$(f_EXTRACT_IP_ALL "$temp/curlw")
  [[ -n "$proxy" ]] && echo -e " -> $proxy  ->  $remote_ip" || echo -e " -> $remote_ip"
fi
if [ $target_type = "dnsrec" ]; then
  dom_title=$(f_getTITLE "$temp/page")
  srv_header=$(grep -sEi "^server:" $temp/headers | cut -d ':' -f 2- | tail -1 | sed 's/^[ \t]*//;s/[ \t]*$//')
  [[ -n "$dom_title" ]] && echo -e "\n '$dom_title' - $srv_header\n"
fi
}

f_printURL(){
if [ $option_connect = "0" ]; then
  awk -F ']' '{print $1}' $temp/ww | sed 's/\[/ /g' | sed '/^$/d' | tail -1
else
  f_VALUE ":" "$(grep -m 1 '^URL:' $temp/curlw)"
fi
}

f_printWEBHOST(){
f_STRIP_URL "$(f_printURL)"
}

f_WEBHOST_SSL(){
local web_host=$(f_printWEBHOST)
echo | $OPENSSL s_client -connect ${web_host}:443 2>$temp/brief -verify_hostname ${web_host} -brief >> $temp/brief
if grep -oq "CONNECTION ESTABLISHED" $temp/brief; then
  verify=$(f_VALUE ":" "$(grep '^Verification:' $temp/brief)")
  exp=$(echo | $OPENSSL s_client -connect ${web_host}:443 2>/dev/null | $OPENSSL x509 -noout -enddate | grep '=' |
  awk -F'=' '{print $NF}' | awk '{print $1,$2,$4}'); verify=$(f_VALUE ":" "$(grep '^Verification:' $temp/brief)")
  peer=$(f_VALUE ":" "$(grep '^Verified peername:' $temp/brief)")
  [[ -n "$exp" ]] && echo "$verify  ($peer); expires:  $exp"
fi
}

f_SERVER_INSTANCES(){
local web_host=$(f_printWEBHOST)
for srvip in $(cat $temp/web_ips); do
  declare new_curl_array; [[ $srvip =~ $REGEX_IP4 ]] && new_curl_array+=(-s4Lkv) || new_curl_array+=(-s6Lkv)
  $DATE -R > $temp/tstamp
  $CURL -m 15 $webhost "${new_curl_array[@]}" "$ua" --resolve "$webhost:443:[$srv_ip]" --trace-time 2>$temp/verbose -o $temp/p2 -D $temp/h2 -w \
  "URL: %{url_effective}
  HTTP/%{http_version} %{response_code}  | %{remote_ip}  |  Redirs: %{num_redirects} | TimeRE %{time_redirect} s  |  TOTAL: %{time_total} s
  %{remote_ip}" | sed 's/| TimeRE/ -> /' > $temp/curlw
  remote_ip=$(grep -m 1 -sEo "$REGEX_IP46" $temp/curlw)
  cat $temp/h2 | tr [:upper:] [:lower:] > $temp/http
  sed 's/^[ \t]*//;s/[ \t]*$//' $temp/verbose | cut -d ' ' -f 3- | sed 's/^ *//' > $temp/verb
  grep -E ">|<|\*" $temp/verbose | sed 's/*/   /' | sed 's/>/ > /' | sed 's/</ < /' > $temp/curl_verbose
  f_detectCDN; imperva=$(f_IMPERVA)
  [[ $remote_ip != $srv_ip ]] && ip_request=" (requested: $srv_ip) " && echo $remote_ip >> $temp/ips_other
  srv_header=$(grep -sEi "^server:" $temp/h2 | cut -d ':' -f 2- | tail -1 | sed 's/^[ \t]*//;s/[ \t]*$//')
  echo -e "\n*   $rem_ip  $ip_request $print_srv_header\n"
  f_printSTATUS | sed 's/^/   /'
  [[ $imperva = "false" ]] && page_sha=$(sha1sum $temp/p2 | awk '{print $1}') && echo -e "\n$page_sha  (Page SHA1)\n"
  f_printHANDSHAKE "$srvip"
done
}

#------------------------------- SSL HANDSHAKE / HTTP CONNECT -------------------------------

f_handshakeHEADER(){
local s="$*"; f_HEADLINE "HTTP REDIRECTS, SSL HANDSHAKE |  $s  | $file_date"
echo -e "\nCLIENT\n" ; echo -e "$(/usr/bin/hostname)\n"
[[ -f $temp/host_nds ]] && echo -e "\nTARGET\n" && cat $temp/host_dns || f_printADDR "$temp/web_ips"
echo ''; grep -sE "URL|\|" $temp/curlw | tail -2 | sed '/HTTP/{x;p;x;G}' | sed '/URL:/{x;p;x;}' | sed 's/^URL://' | sed 's/^ *//'
}

f_printHANDSHAKE(){
timestmp="($(cat $temp/tstamp | sed 's/^[ \t]*//;s/[ \t]*$//'))"; f_HEADLINE2 "$1  $timestmp\n" >> $temp/hndshake
f_printSTATUS >> $temp/hndshake; echo '' >> $temp/hndshake; f_Long >> $temp/hndshake
f_SSL_HANDSHAKE "$temp/curl_verbose" >> $temp/hndshake
}

f_SSL_HANDSHAKE(){
local s="$*"; echo ''; sed '/^$/d' $s | sed 's/ = /=/' |
grep -E -i "HTTP/.*|HTTP1.*|HTTP2|Re-using|\* Connection|TCP_NODELAY|ALPN|ID|SSL connection|SSL certificate|server:|Server certificate:|> GET|> HEAD|handshake|connected to|expire|squid|via:|location:|proxy|x-client-location:|x-varnish|accepted to use|CN=|date:|content-length:|SPDY|cache-control:|content-length:|www-authenticate:|x-cache:" | sed '/P3P:/d' | sed '/[Ff]eature-[Pp]olicy:/d' | sed '/[Pp]ermissions-[Pp]olicy:/d' |
sed '/Server [Cc]ertificate:/a \___________________________________\n' | sed '/[Cc]ontent-[Ss]ecurity-[Pp]olicy:/d' |
sed '/SSL connection using/i \\n---------------------------------------------------------------------\n' |
sed '/Connected to /a \________________________________________________________________________\n\n' |
sed '/Connected to /i \\n________________________________________________________________________\n' |
sed '/Server certificate:/{x;p;x;}' | sed -e :a -e 's/\(.*[0-9]\)\([0-9]\{4\}\)/\1/;ta' | sed '/[Cc]ontent-[Ll]anguage/d' |
sed '/SSL [Cc]ertificate verify/a \\n---------------------------------------------------------------------\n' | fmt -w 120 -s; echo -e "\n"
}

f_getCMS(){
cms=""; cms_comment=""; meta_gen=""; powered_by=""
if [ -f $temp/ww ]; then
  pow_by=$(sed 's/X-Powered-By//' $temp/ww | grep -soP 'Powered-By\[\K.*?(?=\])' | sort -bifu)
  meta_gen=$(f_getWW_ITEM "MetaGenerator" | sort -bifu)
  cms=$(grep -sEaoi -m 1 "1024-CMS|bitrix|contao|drupal|joomla|librecms|liferay|pluck-cms|pragmamx|typo3|wordpress" $temp/ww |
  tr [:lower:] [:upper:] | sort -uV | tail -1)
else
  if [ $option_connect != "0" ]; then
    [[ $ww = "false" ]] && cms_comment="(enable source 'WhatWeb' to improve detection)"
    if [ -z "$meta_gen" ] && [ -f $temp/metas ]; then
      meta_gen=$(grep -sEi "name=(\")?generator" $temp/metas | grep -sioP 'content=\"\K.*?(?=\")' |
      sed 's/^[ \t]*//;s/[ \t]*$//' | sort -bfiu | tr '[:space:]' ' '; echo '')
    fi
    if [ -f $temp/cms_source ]; then
      cms=$(grep -sEoi "api\.w\.org|advagg_|contao|drupal|liferay-portal|jimdo|joomla|/skin/frontend/|typolight\.css|typo3|wp-(admin|content|includes|plugins)|wordpress" $temp/cms_source  | tr [:upper:] [:lower:] | sed 's/advagg_/drupal/g' | sed 's/typolight.css/contao/g' | sed 's/liferay-portal/liferay/g' |
      sed 's/skin\/frontend\//magento/g' | sed 's/api.w.org/wordpress/g' | sed 's/wp-admin/wordpress/g' | sed 's/wp-content/wordpress/g' |
      sed 's/wp-includes/wordpress/g' | sed 's/wp-plugins/wordpress/'| tr [:lower:] [:upper:] | sort -uV | tail -1)
    fi
  fi
fi
[[ -n "$cms" ]] && echo -e "CMS:          $cms $cms_comment" || echo -e "CMS:          none/unknown  $cms_comment"
[[ -n "$meta_gen" ]] && echo -e "MetaGen:      $meta_gen"
[[ -n "$powered_by" ]] && echo -e "PoweredBy:    $powered_by"
}

f_getDOCTYPE(){
local webpage="$*"
if [ $option_connect = "0" ] && [ -f $temp/ww ]; then
  html_5=$(grep -sow -m 1 'HTML5' $temp/ww); [[ -n "$html_5" ]] && echo -e "HTML5:        true" || echo -e "HTML5:         false"
else
  doctype=$(grep -E -i "<\!doctype" $temp/page_tmp | grep -sEoi "XHTML.[1-2]|HTML.[1-4]|<\!doctype html>" | tr [:lower:] [:upper:] |
  sed 's/<!DOCTYPE HTML>/HTML5/'); [[ -n "$doctype" ]] && echo "Doctype:      $doctype"
fi
}

f_getHTTP_SERVER(){
local headers_file="$*"
if [ -f $temp/ww ]; then
  server_redirs=$(f_getWW_ITEM "HTTPServer" | sort -bfiu | wc -l)
else
  server_redirs=$(grep -sEiw "^server:" $headers_file | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | sort -bfiu | wc -l)
fi
if [[ $server_redirs -gt 0 ]]; then
  if [[ $server_redirs -gt 1 ]]; then
    [[ -f $temp/ww ]] && server_header=$(grep -s -oP '(HTTPServer\[).*?(?=\,)' $temp/ww | sed 's/HTTPServer\[/=>/' | tr -d ']')
    [[ -z "$server_header" ]] && [[ $option_connect != "0" ]] && server_header=$(grep -sEiw "^server:" $headers_file | sed 's/[Ss]erver:/=>/g')
    print_serv=$(f_printHEADER_ITEM "$server_header")
  else
    if [ -f $temp/ww ]; then
      print_serv=$(f_getWW_ITEM "HTTPServer" | tail -1)
    else
      print_serv=$(grep -sEiw "^server:" $headers_file | tail -1 | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' '; echo '')
    fi
  fi
  [[ -n "$print_serv" ]] && echo -e "Server:       $print_serv" || echo -e "Server:       Unknown"
fi
}

f_getMETA_TAGS(){
if [ -f $temp/metas ]; then
  if [[ $(grep -sEiac "title|description|keywords|og:title|og:description" $temp/metas) -gt 0 ]]; then
    page_title=$(f_getTITLE "$temp/page" | awk -F'Title:' '{print $2}' | sed 's/^[ \t]*//;s/[ \t]*$//')
    meta_title=$(grep -sEai "name=title|name=\"title" $temp/metas | grep -sioP 'content=\"\K.*?(?=\")')
    meta_descr=$(grep -sEai "name=description|name=\"description" $temp/metas | grep -sioP 'content=\"\K.*?(?=\")')
    meta_keyw=$(grep -sEai "name=keywords|name=\"keywords" $temp/metas | grep -sioP 'content=\"\K.*?(?=\")')
    og_type=$(grep -sEai "property=og:type|property=\"og:type" $temp/metas | grep -sioP 'content=\"\K.*?(?=\")')
    og_title_raw=$(grep -sEai "property=og:title|property=\"og:title" $temp/metas | grep -sioP 'content=\"\K.*?(?=\")')
    [[ -n "$og_title_raw" ]] && og_title=$(f_HTML_DECODE "$og_title_raw")
    og_descr=$(grep -sEai "property=og:description|property=\"og:description" $temp/metas | grep -sioP 'content=\"\K.*?(?=\")')
    og_publisher=$(grep -sEai "property=article:publisher|property=\"article:publisher" $temp/metas | grep -sioP 'content=\"\K.*?(?=\")')
    og_url=$(grep -sEai "property=og:url|property=\"og:url" $temp/metas | grep -sioP 'content=\"\K.*?(?=\")')
    echo ''; f_Long
    [[ -n "$meta_descr" ]] && echo -e "\nDESCRIPTION\n" && f_HTML_DECODE "$meta_descr" | fmt -s -w 80
    [[ -n "$meta_keyw" ]] && echo -e "\nKEYWORDS\n" && echo -e "$meta_keyw" | sed 's/,/, /g' | sed 's/^\,//' | sed 's/^ *//' | fmt -s -w 80
    [[ -n "$print_title" ]] && echo -e "\nMETA  TITLE\n" && f_HTML_DECODE "$meta_title"
    if [[ $(grep -sEic "og:title|og:description" $temp/metas) -gt 0 ]]; then
      [[ -n "$meta_descr" ]] || [[ -n "$meta_keyw" ]] && echo ''
      echo -e "\nOPEN-GRAPH-PROTOCOL\n"
      if [ -n "$og_title" ]; then
        [[ "$og_title" = "$page_title" ]] && echo -e "Title:  Matches website title" || echo -e "Title:  $og_title"
      fi
      [[ -n "$og_url" ]] &&  echo -e "URL:    $og_url" || echo -e "URL:    No URL provided for $x"
      [[ -n "$og_publisher" ]] && echo -e "Publish.: $og_publisher"
      if [ -n "$og_descr" ]; then
        [[ "$og_descr" = "$meta_descr" ]] && echo -e "Descr:  Matches meta description" || echo -e "\nDescription:\n\n$og_descr"
      fi
    fi
  fi
fi
}

f_getSCRIPTS(){
unset script_types; [[ -f $temp/jqu ]] && rm $temp/jqu; [[ -f $temp/php ]] && rm $temp/php;
[[ -f $temp/scripts ]] && rm $temp/scripts; [[ -f $temp/types ]] && rm $temp/types
if [ -f $temp/ww ]; then
  f_getWW_ITEM "Script" | sed 's/,/\n/g' | sed 's/^[ \t]*//;s/[ \t]*$//' > $temp/types
  grep -s -oP '(JQuery\[).*?(?=\])' $temp/ww | sed 's/\[/./g' >> $temp/jqu
  [[ -f $temp/jqu ]] || grep -sio -m 1 'jquery' $temp/ww >> $temp/jqu
  f_getWW_ITEM "PHP" >> $temp/php; [[ -f $temp/php ]] || grep -sio -m 1 'php' $temp/ww >> $temp/php
else
  if [ $option_connect != "0" ]; then
     grep 'type' $temp/page_scripts | 
     grep -sEaio "module|text/(csv|dns|ecmascript|javascript|markdown|plain)|application/(ecmascript|javascript|json|ld\+json|settings\+json)" |
     sort -bifu > $temp/types
    if [ -f $temp/page_scripts ]; then
      grep -sEoi "jquery+(\.min\.js)?+(\?ver=)?+(/)?+(/\?=)?+[0-9\.-/_x]{1,6}" $temp/page_scripts | tr -d '/' | sed 's/min.js//' |
      sed 's/.?ver=/_/' | sed 's/?ver=/_/' | sort -bifuV | tail -1 > $temp/jqu
    fi
    grep -sEoi "PHP+[-_/\.]+[0-9x]+[-_/\.]+[0-9x]{1,2}(+[-_/\.]+[0-9x]{1,2})?+([-_/\.]+[0-9x]{1,2})?" $temp/headers |
    sort -bifuV > $temp/php
    grep -sEi "^x-generator:|^x-powered-by:|^set-cookie:" $temp/headers | grep -io -m 1 'php' >> $temp/php
  fi
fi
[[ -f  $temp/types ]] && script_types=$(sort -u $temp/types | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ')
if [ -z "$script_types" ] || [[ $(f_countW "$script_types") -eq 0 ]]; then
  if [ -f $temp/ww ]; then
    grep -o -m 1 'Script' $temp/ww | sed 's/Script/Script\[unknown_type\]/' > $temp/scripts
  else
    [[ -f $temp/page_scripts ]] && grep -io -m 1 '<script' $temp/page_scripts | sed 's/<script/Script\[generic\]/' > $temp/scripts
  fi
else
  echo "$script_types" > $temp/scripts
fi
[[ -f $temp/jqu ]] && sort -bifu $temp/jqu | tail -1 >> $temp/scripts
[[ -f $temp/php ]] && f_toUPPER "$(sort -uV $temp/php | tail -1)" >> $temp/scripts
if [ -f $temp/scripts ]; then
  scripts_raw=$(sed 's/jquery/JQuery/' $temp/scripts)
  print_scripts=$(echo "$scripts_raw" | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' | sed 's/ /  /g'; echo '')
  if [[ $(f_countW "$print_scripts") -gt 0 ]]; then
    [[ $(f_countW "$print_scripts") -lt 9 ]] && echo -e "Script:       $print_scripts" || echo -e "\nScript:\n\n$print_scripts\n"
  fi
fi
}

f_getTITLE(){
local f="$*"; [[ $target_type != "dnsrec" ]] && [[ -f $temp/ww ]] && title_raw=$(f_getWW_ITEM "Title" | tail -1)
if [ -z "$title_raw" ] && [ $option_connect != "0" ]; then
  title_raw=$(grep -sioP '<title>\K.*?(?=</title>)' $f | head -1)
fi
if [ -n "$title_raw" ]; then
  title=$(f_HTML_DECODE "$title_raw")
  [[ $target_type = "dnsrec" ]] && echo "$title" || echo -e "\nTitle:        $title"
fi
}

f_HTML_DECODE(){
echo "$1" | sed 's/&#8211;/-/g' | sed 's/\&amp;/\&/g' | sed "s/&#39;/\'/g" | sed 's/&#64;/@/g' | sed 's/&#x40;/@/g' |
sed 's/&#42;/*/g' | sed 's/&#x2A;/*/g' | sed 's/&#43;/+/g' | sed 's/&#x2B/+/g' | sed 's/&uuml;/ü/g' | sed 's/&auml;/ä/g' |
sed 's/&ouml;/ö/g' | sed 's/^[ \t]*//;s/[ \t]*$//'
}

f_getTXTS(){
local web_host=$(f_printWEBHOST)
[[ -f $temp/humans ]] && rm $temp/humans
[[ -f $temp/security ]] && rm $temp/security
[[ -f $temp/robots ]] && rm $temp/robots
status_humans=$($CURL -sLk ${web_host}/humans.txt -o $temp/humans -w %{response_code})
if [ $status_humans = "200" ]; then
  mv $temp/humans $temp/humans.txt
  if [[ $(grep -ic "DOCTYPE" $temp/humans.txt) -gt 0 ]]; then
    echo "humans.txt: false" >> $temp/server_files
  else
    if [[ $(wc -w < $temp/humans.txt) -lt 1 ]]; then
      echo "| humans.txt: empty file" >> $temp/server_files; rm $temp/humans.txt
    else
      cat $temp/humans.txt >> $temp/cms; echo "humans.txt: true" >> $temp/server_files
      f_HEADLINE "$s | humans.txt | $file_date" > ${outdir}/HUMANS.TXT.${s}.txt
      cat $temp/humans.txt >> ${outdir}/HUMANS.TXT.${web_host}.txt
    fi
  fi
  [[ $page_details = "false" ]] && rm $temp/humans.txt
else
  echo "humans.txt: false" >> $temp/server_files
fi
status_security=$($CURL -sLk ${web_host}/security.txt -o $temp/security -w %{response_code})
if [ $status_security = "200" ]; then
  mv $temp/security $temp/security.txt
  if [[ $(grep -ic "DOCTYPE" $temp/security.txt) -gt 0 ]] || [[ $(wc -w < $temp/security.txt) -gt 600 ]]; then
    echo "| security.txt: false" >> $temp/server_files
  else
    if [[ $(wc -w < $temp/security.txt) -lt 1 ]]; then
      echo "| security.txt: empty file" >> $temp/server_files; rm $temp/security.txt
    else
      echo "| security.txt: true" >> $temp/server_files
      f_HEADLINE "$s | security.txt | $file_date" > ${outdir}/SECURITY.TXT.${web_host}.txt
      cat $temp/security.txt >> ${outdir}/SECURITY.TXT.${s}.txt
    fi
  fi
  [[ $page_details = "false" ]] && rm $temp/security.txt
else
  echo "| security.txt: false" >> $temp/server_files
fi
status_robots=$($CURL -sLk ${web_host}/robots.txt -o $temp/robots -w %{response_code})
if [ $status_robots = "200" ]; then
  mv $temp/robots $temp/robots.txt
    if [[ $(grep -i -c "DOCTYPE" $temp/robots.txt) -gt 0 ]]; then
      echo "| robots.txt: false" >> $temp/server_files
    elif [[ $(grep -Eic "User-agent|Allow:|Disallow:|Sitemap:" $temp/robots.txt) -lt 1 ]]; then
      echo "| robots.txt: false" >> $temp/server_files
    else
      if [[ $(wc -w < $temp/robots.txt) -lt 1 ]]; then
        echo "| robots.txt: empty file" >> $temp/server_files; rm $temp/robots.txt
      else
        cat $temp/robots.txt >> $temp/cms_src; echo "| robots.txt: true" >> $temp/server_files
        f_HEADLINE "$s | robots.txt | $file_date" > ${outdir}/ROBOTS.TXT.${web_host}.txt
        cat $temp/robots.txt >> ${outdir}/ROBOTS.TXT.${web_host}.txt
      fi
    fi
  [[ $page_details = "false" ]] && rm $temp/robots.txt
else
  echo "| robots.txt: false" >> $temp/server_files
fi
[[ -f $temp/robots.txt ]] && cat $temp/robots.txt >> $temp/cms_src
[[ -f $temp/humans.txt ]] && cat $temp/humans.txt >> $temp/cms_src
status_manifest=$($CURL -sLk ${web_host}/manifest.json -o $temp/manifest.json -w %{response_code})
if [ $status_manifest != "200" ]; then
  status_manifest=$($CURL -sLk ${web_host}/site.webmanifest -o $temp/manifest.json -w %{response_code})
fi
if [ $status_manifest != "200" ]; then
  if [[ $(grep -ic "DOCTYPE" $temp/manifest.json) -eq 0 ]] || [[ $(wc -w < $temp/manifest.json) -lt 600 ]]; then
    mv $temp/manifest.json $temp/manifest; cat $temp/manifest >> $temp/cms_src
  fi
fi
[[ -f $temp/manifest.json ]] && rm $temp/manifest.json
}

f_getWEB_OTHER(){
google_ua=""; web_other=""
if [ -f $temp/ww ]; then
  web_other=$(grep -sEoi "Adobe-Flash|AWStats|AzureCloud|Bootstrap|ColdFusion|Confluence|Fortiweb|Frame|highlight\.js|Lightbox|Modernizr|Incapsula-WAF|Open-Cart|OpenSearch|Prototype|Scriptaculous|Shopify|Varnish|Vimeo|Youtube" $temp/ww |
  sed 's/^[ \t]*//;s/[ \t]*$//' | sort -bifu | sed 's/Prototype/Prototype JS/' | tr '[:space:]' ' '; echo '')
  cxnsc=$(f_getWW_ITEM "Citrix-NetScaler"); blb=$(f_getWW_ITEM "Barracuda-Load-Balancer"); bwaf=$(f_getWW_ITEM "Barracuda-Waf")
  google_ua=$(f_getWW_ITEM "Google-Analytics" | grep -sEoi "UA-[0-9-]{3,11}")
  og=$(grep -sEo -m 1 "Open-Graph-Protocol" $temp/ww); og_type=$(f_getWW_ITEM "Open-Graph-Protocol")
  [[ -n "$google_ua" ]] && echo "$google_ua" > $temp/web_tmp
else
  [[ -f $temp/metas ]] && og=$(grep -sEia "og:(type|url|title|description)" $temp/metas | grep -o -m 1 'og' | sed 's/og/Open-Graph-Protocol/')
fi
if [ $option_connect != "0" ]; then
  [[ -z "$google_ua" ]] && grep -so "\.googletagmanager\." $temp/page_scripts | sed 's/.googletagmanager./GoogleTagManager/' | tail -1 >> $temp/web_tmp
  grep -sEo "fonts\.googleapis|fonts\.gstatic" $temp/site_src | grep -o 'fonts' | tail -1 | sed 's/fonts/GoogleFonts/' >> $temp/web_tmp
fi
grep -sEoi "application/rss\+xml" $temp/page | grep -soi -m 1 'rss' | tr [:lower:] [:upper:] >> $temp/web_tmp
if [ -n "$og" ]; then
  [[ -n "$og_type" ]] && echo "Open-Graph-Protocol[$og_type]" >> $temp/web_tmp || echo "Open-Graph-Protocol" >> $temp/web_tmp
fi
  [[ -n "$web_other" ]] && echo "$web_other" >>  $temp/web_tmp; [[ -n "$blb" ]] && echo "$blb" >> $temp/web_tmp
  [[ -n "$bwaf" ]] && echo "$bwaf" >> $temp/web_tmp; [[ -n "$cxnsc" ]] && echo "$cxnsc" >> $temp/web_tmp
  [[ -f $temp/cdn ]] && cat $temp/cdn >> $temp/web_tmp
if [[ $(wc -w < $temp/web_tmp) -gt 0 ]]; then
  print_other=$(sed 's/^[ \t]*//;s/[ \t]*$//' $temp/web_tmp | tr '[:space:]' ' ' | sed 's/ /  /g'; echo '')
  echo "Other         $print_other"
fi
}

f_HTML_COMMENTS(){
local web_host=$(f_printWEBHOST)
if [ "$x" != "$web_host" ]; then
  $NMAP -Pn -sT -p 80,443 --script http-comments-displayer $x 2>/dev/null > $temp/comments; comments=$(f_printCOMMENTS)
  [[ -n "$comments" ]] && echo -e "\n$x  HTML Comments\n" && echo -e "$comments\n" && comments=""
else
  echo ''
fi
$NMAP -Pn -sT -p 80,443 --script http-comments-displayer $web_host 2>/dev/null > $temp/comments; comments=$(f_printCOMMENTS)
[[ -n "$comments" ]] && echo -e "\n$web_host  HTML Comments\n" && echo -e "$comments\n"; comments=""
}

f_printCOMMENTS(){
if [ -f $temp/comments ]; then
  grep -E "80/tcp|443/tcp|\||\|_" $temp/comments | tr -d '|_' | sed 's/^ *//' | sed 's/Line number:/ | Line:/g' |
  tr '[:space:]' ' ' | sed 's/Comment:/\n/g' | sed 's/443\/tcp/\n443\/tcp/' | sed 's/Path:/\n\nPath:/g' |
  sed '/\/tcp/{x;p;x;G;}' | sed 's/http-comments-displayer:/\n\n/' | sed 's/^ *//' | sed 's/<\!--/    <\!--/g' |
  sed 's/\/\*/    \/\*/g' | fmt -s -w 100; echo ''; rm $temp/comments
fi
}

f_LINK_DUMP(){
[[ -f $temp/print_ld ]] && rm $temp/print_ld; [[ -f $temp/urls ]] && rm $temp/urls
[[ -f $temp/link_urls ]] && rm $temp/link_urls; [[ -f $temp/src_urls ]] && rm $temp/src_urls
if [ -f $temp/ldump_raw ]; then
  grep -E -v "*.cc.ukansas|*.cc.ukans*|*.cc.ku.edu*|invisible-island.net|lynx.invisible-island.net|lynx-dev|lynx_help|NCSAMosaicHome.html|www.w3.org/People" $temp/ldump_raw | sed '/javascript:void(0)/d' | sed '/[Vv]isible [Ll]inks:/d' | sed '/[Hh]idden [Ll]inks:/d' |
  sed '/Sichtbare Links:/d' | sed '/Versteckte Links:/d' | sort -f -u  > $temp/ldump
  grep -sEi "http:|https:" $temp/ldump > $temp/urls
  echo '' > $temp/linkdump; f_HEADLINE3 "[WEBSITE]  $target   LINK DUMP   $file_date" >> $temp/linkdump
  cat $temp/ldump | sed '/^$/d' >> $temp/print_ld; echo '' | tee -a $temp/linkdump >> $temp/print_ld
  hosts_unique=$(f_STRIP_URL "$(grep -sEi "http:|https:" $temp/urls)" | sort -ifu)
  if [ -n "$hosts_unique" ]; then
    echo '' >> $temp/print_ld; f_Long >> $temp/print_ld; echo '' >> $temp/print_ld
    for u in $hosts_unique ; do
      host_addr=$($DIG +short $u | grep -sEo "$REGEX_IP4" | head -2 | tr '[:space:]' ' ')
      echo -e "$u  -  $host_addr\n"
    done > $temp/links_resolved
    cat $temp/links_resolved >> $temp/print_ld; f_EXTRACT_IP4 "$temp/links_resolved" > $temp/ldump_ips
    f_Long | tee -a $temp/links_resolved >> $temp/print_ld
    f_WHOIS_TABLE "$temp/ldump_ips"  | tee -a $temp/links_resolved >> $temp/print_ld
  fi
  [[ $report = "true" ]] && cat $temp/linkdump > ${outdir}/LINK_DUMP.$1.txt && cat $temp/print_ld >> ${outdir}/LINK_DUMP.$1.txt
fi
}

f_PAGE(){
local web_host=$(f_printWEBHOST)
local target_url=$(f_printURL)
if [ $option_connect = "0" ]; then
  f_WHATWEB
else
  imperva=$(f_IMPERVA); target_ip=$(f_EXTRACT_IP_ALL "$temp/curlw")
  if [ $imperva = "false" ]; then
    if type lynx &> /dev/null; then
      $TOUT 10 $LYNX -accept_all_cookies -crawl -dump -nonumbers $x 2>/dev/null > $temp/pages_text
      $TOUT 10 $LYNX -accept_all_cookies -crawl -dump -nonumbers $target_url  2>/dev/null >> $temp/pages_text
      $TOUT 10 $LYNX -accept_all_cookies -dump -listonly -nonumbers $target_url  2>/dev/null > $temp/ldump_raw
      $TOUT 10 $LYNX -accept_all_cookies -crawl -dump -nonumbers $web_host  2>/dev/null >> $temp/pages_text
      $TOUT 10 $LYNX -accept_all_cookies -dump -listonly -nonumbers $web_bhost  2>/dev/null >> $temp/ldump_raw
    fi
    if [ -f $temp/pages_text ]; then
      iframes=$(grep 'IFRAME:' $temp/pages_text | sort -u | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' |
      tr '[:space:]' ' '; echo '')
    fi
    f_LINK_DUMP "$web_host"; scripts=$(f_getSCRIPTS); web_other=$(f_getWEB_OTHER); apph=$(f_getAPP_HEADERS "$temp/headers")
    if [ -f $temp/server_files ]; then
      server_files=$(cat $temp/server_files | tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/^\|//' | sed 's/^ *//')
      rm $temp/server_files
    fi
  fi # imperva = false
  f_HEADLINE3 "[WEBSITE]  $web_host"; f_printSTATUS; echo ''
  if [ $imperva = "true" ]; then
    echo -e "\nTARGET WEBSITE:\n\nImperva Incapsula detected.\n\nAborting attemps to scrape website..."
  else
    f_Long; f_getTITLE "$temp/page"; echo ''; f_getHTTP_SERVER "$temp/headers"; f_getCMS; f_getDOCTYPE
    [[ -n "$scripts" ]] && echo "$scripts"
    [[ -n "$apph" ]] && echo "AppHeaders:   $apph"
    author=$(grep -sEai "name=author|name=\"author" $temp/metas | grep -sioP 'content=\"\K.*?(?=\")')
    [[ -n "$author" ]] && echo "Author:       $author"; [[ -n "$auth" ]] &&  echo "Auth:         $auth"
    [[ -f $temp/ww ]] && grep -soP '(PasswordField\[).*?(?=\])' $temp/ww | sed 's/PasswordField\[/PasswdField:  /' | tr -d ']'
    [[ -n "$web_other" ]] && echo "$web_other"; [[ $(echo "$iframes" | wc -w) -gt 0 ]] && echo "Frame:        $iframes"
    rss_feeds=$(grep "<link" $temp/page | grep "application/rss+xml" | awk -F'href=' '{print $2}' | grep -oaEi "https?://[^\"\\'> ]+")
    if [ -n "$rss_feeds" ]; then
      rss_link=$(echo "$rss_feeds" | head -1); print_rss_links=$(echo "$rss_raw" | tr '[:space:]' ' ' | sed 's/ /  /'; echo '')
      $CURL -sLk $rss_link > $temp/rss
      rss_generator=$(grep -sioP '<generator>\K.*?(?=</generator>)' $temp/rss | head -1)
      echo -e "\nRSS Feed:     $print_rss_links"
      [[ -n "$rss_generator" ]] && echo -e "\nGenerator:    $rss_generator"
    fi
    if [[ $(f_countW "$temp/web_ips") -eq 1 ]]; then
      echo -e "\n\nPage SHA1:    $(sha1sum $temp/page_tmp | awk '{print $1}')"
    fi
    echo -e "\nTXTs:         $server_files"
  fi # imperva = false
  f_getCOOKIES
  if [[ $(f_countW "$temp/web_ips") -eq 1 ]] && [ $send_ping = "true" ]; then
    f_Long; [[ $target_ip =~ $REGEX_IP6 ]] && opt_v6="-6"
    $NPING $opt_v6 --safe-payloads --tcp-connect -p 80 -c 5 $target_ip > $temp/np; f_PING "$target_ip"; opt_v6=""
    f_Long; echo -e "SECURITY HEADERS\n"
  else
    f_HEADLINE2 "SECURITY HEADERS\n"
  fi
  f_getSEC_HEADERS "$temp/h3"
  if [[ $imperva = "false" ]] && [[ $page_details = "true" ]]; then
    f_getMETA_TAGS
    [[ -f $temp/rss ]] && feeds=$(grep -sioP '<title\K.*?(?=</title>)' $temp/rss)
    if [ -n "$feeds" ]; then
      f_HEADLINE2 "RSS ($rss_link)"; echo -e "\n$feeds\n"
    fi
    f_SOCIAL "$web_host"
    if [ $domain_enum = "true" ] && [ -f $temp/links_resolved ]; then
      f_HEADLINE2 "WEBSITE LINKING TO:\n\n"; cat $temp/links_resolved
    fi
  fi
fi # option_connect != 0
}

f_printTXTS(){
if [ -f $temp/robots.txt ]; then
  [[ $(wc -l < $temp/robots.txt) -lt 41 ]] && print_robots="ROBOTS.TXT\n\n$(cat $temp/robots.txt)"; rm $temp/robots.txt
fi
if [ -f $temp/humans.txt ]; then
  if [[ $(wc -l < $temp/humans.txt) -lt 41 ]]; then
    [[ $domain_enum = "true" ]] && echo '' && f_Long; print_humans="HUMANS.TXT\n\n$(cat $temp/humans.txt)"
    [[ $domain_enum = "true" ]] && [[ -z "$print_robots" ]] && f_HEADLINE2 "HUMANS.TXT\n"
    [[ -n "$print_robots" ]] && echo ''; echo -e "$print_humans"; rm $temp/humans.txt
  fi
fi
if [ -f $temp/security.txt ]; then
  if [[ $(wc -l < $temp/security.txt) -lt 41 ]]; then
    print_security="SECURITY.TXT\n\n$(cat $temp/security.txt)"
    [[ -n "$print_robots" ]] || [[ -n "$print_humans" ]] && echo -e "\n"; echo -e "$print_security"
  fi
  rm $temp/security.txt
fi
if [ -f $temp/manifest ] && [[ $(wc -l < $temp/manifest) -lt 41 ]]; then
  if [ -n "$print_robots" ] || [ -n "$print_humans" ] || [ "$print_security" ]; then
    f_HEADLINE2 "MANIFEST.JSON"
  else
    echo -e "\nMANIFEST.JSON\n"
  fi
  cat $temp/manifest; rm $temp/manifest
fi
}

f_PAGE_ADDITIONS(){
local web_host=$(f_printWEBHOST); txts=$(f_printTXTS)
if [ $page_details = "true" ]; then
  f_HEADLINE3 "[WEBSITE]  $web_host  ADDITIONAL DATA"
if [ $option_web_test != "1" ]; then
    [[ -n "$txts" ]] && echo "$txts" && echo '' && f_Long
  fi
  if [ $option_web_test = "2" ] || [ $option_web_test = "3" ]; then
    f_HTML_COMMENTS; f_Long
  else
    echo ''
  fi
  echo -e "\n$web_host HTTP HEADERS\n\n"; cat $temp/headers | fmt -s -w 100
  if [ $option_web_test = "1" ] || [ $option_web_test = "3" ] || [ $domain_enum = "true" ]; then
    [[ -f $temp/print_ld ]] && echo '' && f_HEADLINE3 "[LINK DUMP]  $web_host" && echo '' && cat $temp/print_ld
  fi; echo ''
else
  f_HEADLINE2 "$web_host  HTTP HEADERS\n" ; cat $temp/headers | fmt -s -w 100
fi
}

f_SOCIAL(){
local s="$*"
[[ -f $temp/mail ]] && rm $temp/mail; [[ -f $temp/phone ]] && rm $temp/phone
[[ -f $temp/ww ]] && f_EXTRACT_EMAIL "$(grep -s -oP '(Email\[).*?(?=])' $temp/ww)" >> $temp/mail
for site in $subpages; do $CURL -sLk ${curl_ua} ${s}/${site}; done > $temp/pages
cat $temp/page >> $temp/pages; cat $temp/ldump_raw >> $temp/pages
cat $temp/pages >> $temp/pages2; cat $temp/pages_text >> $temp/pages2
for site2 in $subpages2; do $CURL -sLk ${curl_ua} ${site2}.${s}; done >> $temp/pages
grep -sEo "\b[A-Za-z0-9._%+-]+(@|\s\(at\)\s|-at-|\(at\)|_AT_)[A-Za-z0-9.-]+(_DOT_|-dot-|\.)[A-Za-z]{2,6}\b" $temp/pages2 | tr -d ' ' >> $temp/mail
grep -sEi "(.*.)?(contact|mail|phone|phon|telef|kontakt|support|customer|sales|careers|karriere)(.*.)?" $temp/pages2 |
grep -sEo "$REGEX_PHONE" > $temp/phone; grep -sEi "tel:|fon:|mobil.*|cell.*" $temp/pages2 | grep -sEo "$REGEX_PHONE" >> $temp/phone
grep -sEai "contact|kontakt|support|career|karriere" $temp/ldump > $temp/social_tmp
grep -E "^http.*" $temp/ldump > $temp/ldump_urls; grep -A 1 '<link' $temp/pages | grep -sE "rel=\"(publisher|me)" |
grep -sioP 'href="\K.*?(?=")' | grep -E "^http.*" >> $temp/ldump_urls
[[ $x =~ "codepen" ]] || grep -sEai "codepen" $temp/ldump_urls >> $temp/social_tmp
[[ $x =~ "discord" ]] || grep -sEai "discord" $temp/ldump_urls >> $temp/social_tmp
[[ $x =~ "github" ]] || grep -sEai "github" $temp/ldump_urls >> $temp/social_tmp
[[ $x =~ "facebook" ]] || grep -sEai "facebook" $temp/ldump_urls >> $temp/social_tmp
[[ $x =~ "instagram" ]] || grep -sEai "instagram" $temp/ldump_urls >> $temp/social_tmp
[[ $x =~ "linkedin" ]] || grep -sEai "linkedin" $temp/ldump_urls >> $temp/social_tmp
[[ $x =~ "mastodon" ]] || grep -sEai "mastodon" $temp/ldump_urls >> $temp/social_tmp
[[ $x =~ "pinterest" ]] || grep -sEai "pinterest" $temp/ldump_urls >> $temp/social_tmp
[[ $x =~ "telegram" ]] || grep -sEai "telegram" $temp/ldump_urls >> $temp/social_tmp
[[ $x =~ "threma" ]] || grep -sEai "threma" $temp/ldump_urls >> $temp/social_tmp
[[ $x =~ "twitter" ]] || grep -sEai "twitter" $temp/ldump_urls >> $temp/social_tmp
[[ $x =~ "vk.ru" ]] || grep -sEai "vk.ru" $temp/ldump_urls >> $temp/social_tmp
[[ $x =~ "xing" ]] || grep -sEai "xing" $temp/ldump_urls >> $temp/social_tmp
[[ $x =~ "youtube" ]] || grep -sEai "youtube" $temp/ldump_urls >> $temp/social_tmp
social_links=$(sort -bifu $temp/social_tmp)
gmaps=$(grep -sai 'google' $temp/linkdump_urls | grep -sai 'maps' | grep -saiv 'api')
page_mail=$(sort -bifu $temp/mail | grep -E -v "\.jpg|\.png|\.gif|\.tiff|\.ico")
echo ''; f_HEADLINE2 "SOCIAL MEDIA & CONTACTS\n\n"
[[ -n "$social_links" ]] && echo -e "$social_links\n"; [[ -n "$gmaps" ]] && echo -e "$gmaps\n"
[[ -f $temp/phone ]] && [[ $(wc -w  < $temp/phone) -gt 0 ]] && sort -uV $temp/phone && echo ''
[[ -n "$page_mail" ]] && echo "$page_mail" | tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//' |
sed 's/ /  /g' | fmt -w 60; echo ''
}

# ---------------  HOST INFO: GEO IP, BGP, SHODAN, IP REPUTATION  --------------------

f_WEBHOST_INFO(){
web6=$(sort -uV $temp/web6)
if [ -n "$web6" ]; then
    [[ $( wc -w  < $temp/ips_all) -gt 1 ]] && [[ $target_type != "dnsrec" ]] && f_HEADLINE "IPV6 HOSTS" || f_Long
    for z in $web6; do f_HOST_SHORT "$z"; echo ''; done
fi
    for a in $(f_EXTRACT_IP4 "$temp/web4"); do f_HOST_SHORT "$a"; echo ''; done
}

# ---------------------------------  WHATWEB  -----------------------------------------

f_getCOOKIES(){
if [ -f $temp/ww ]; then
  unset cookies; unset cookie_count; unset http_only
  cookies_raw=$(f_getWW_ITEM "Cookies" | sed 's/,/\n/g' | sed 's/^ *//' | sort -bifu)
  cookie_count=$(f_countW "$cookies_raw")
  if [[ $cookie_count -gt 0 ]]; then
    cookies=$(f_printCSV "$cookies_raw"); htonly_raw=$(f_getWW_ITEM "HttpOnly" | sed 's/,/\n/g' | sed 's/^ *//' | sort -bifu)
    echo -e "\nCookies:      $cookies"
    [[ -n "$htonly_raw" ]] && htonly=$(f_printCSV "$htonly_raw")  && echo -e "HttpOnly:     $htonly" || echo -e "HttpOnly:     Flag not set"
  fi
fi
}

f_getUNCOMMON_HEADERS(){
uncommon_raw=$(f_getWW_ITEM "UncommonHeaders" | sed 's/,/\n/g' | sort -bifu)
[[ -n "$uncommon_raw" ]]  && f_printCSV $(echo "$uncommon_raw" | sed 's/^/,/')
}

f_getWW_ITEM(){
grep -soP "$1\[\K.*?(?=],)" $temp/ww | tr -d '[]' | sed 's/,/, /g'
}

f_getWHATWEB(){
if [ $ww = "true" ] && [ $ww_source = "1" ]; then
    $CURL -s -m 50 "https://api.hackertarget.com/whatweb/?q=${x}${api_key_ht}" > $temp/ww_raw
elif [ $ww = "true" ] && [ $ww_source = "2" ]; then
  if type whatweb &> /dev/null; then
    $WHATWEB --no-errors --color=never --user-agent Mozilla/5.0 2>/dev/null $x > $temp/ww_raw
  else
    echo "Unspecified error (WhatWeb)"
  fi
fi
if [ -f $temp/ww_raw ]; then
  [[ $(grep -soP '(IP\[).*?(?=\])' $temp/ww_raw | wc -l) -gt 0 ]] && cat $temp/ww_raw > $temp/ww
fi
}

f_WHATWEB(){
if [ -f $temp/ww ]; then
  [[ -f $temp/sec_headers ]] && rm $temp/sec_headers; get_ips=$(f_getWW_ITEM "IP" | sort -u)
  if [ $domain_enum = "true" ] && [ $option_connect = "0" ]; then
    f_HOST_DNS "$x"; webhost=$(f_getWEBHOST)
    [[ "$x" != "$webhost" ]] && f_HOST_DNS "$webhost" && web_dom=$(f_checkDOMAIN "$webhost") || $web_dom="$x"
    [[ -f $temp/hosts_all ]] && f_Long && f_WHOIS_TABLE "$temp/hosts_all"
    [[ "$x" != "$web_dom" ]] && f_Long && f_WHOIS_STATUS "$webhost"
  fi
  site_title=$(f_getTITLE "$temp/ww"); ww_email=$(f_EXTRACT_EMAIL "$(grep -s -oP '(Email\[).*?(?=])' $temp/ww)")
  if [ -n "$ww_email" ]; then
    print_mail=$(echo "$ww_email" | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//'; echo '')
    mailcount=$(f_countW "$ww_email")
  else
    mailcount=0
  fi
  proxy=$(f_PROXY); get_cookies=$(f_getCOOKIES); ww_other=$(f_getWEB_OTHER); uncommon=$(f_getUNCOMMON_HEADERS); www_auth=$(f_AUTH)
  grep -s -oP '(Strict-Transport-Security\[).*?(?=\])' $temp/ww | tail -1 | sed 's/\[/: /' | tr -d '][' > $temp/sec_headers
  grep -s -oP '(X-Frame-Options\[).*?(?=\])' $temp/ww | tail -1 | sed 's/\[/:  /' | tr -d ']['  >> $temp/sec_headers
  grep -s -oP '(X-XSS-Protection\[).*?(?=\])' $temp/ww | tail -1 | sed 's/\[/:  /' | tr -d ']['  >> $temp/sec_headers
  grep -s -oP '(X-UA-Compatible\[).*?(?=\])' $temp/ww | tail -1 | sed 's/\[/:  /' | tr -d ']['  >> $temp/sec_headers
  if [[ $(f_countW "$get_ips") -gt 1 ]]; then
    print_srv_ips=$(grep -soP '(IP\[).*?(?=\])' $temp/ww | sed 's/IP\[/> /g' | tr '[:space:]' ' ' | sed 's/^ *//')
  else
    print_srv_ips="$get_ips"
  fi
  echo ''; f_Long; echo -e "WHATWEB\n"
  awk -F ']' '{print $1}' $temp/ww | sed 's/\[/ /g' | sed '/^$/d'
  grep -sioP '(Meta-Refresh-Redirect\[).*?(?=])' $temp/ww |
  sed 's/Meta-Refresh-Redirect\[/\nMeta-Refresh:  Redirect to  ->  /';
  [[ -n "$proxy" ]] && echo -e "\n-> $proxy\n\n -> $print_srv_ips\n" || echo -e "\n-> $print_srv_ips\n"
  [[ -n "$site_title" ]] && echo -e "$site_title\n"; f_getHTTP_SERVER
  f_getCMS; f_getDOCTYPE; f_getSCRIPTS; f_getAPP_HEADERS
  m_author=$(f_getWW_ITEM "Meta-Author"); cont_lang=$(f_getWW_ITEM "Content-Language")
  [[ -n "$cont_lang" ]] && print_lang=$(echo "$cont_lang" | grep -sEoi -m 1 "[a-z]{2}") && echo "Language:     $print_lang"
  [[ -n "$m_author" ]] && echo "Author:       $m_author"
  grep -soP '(PasswordField\[).*?(?=\])' $temp/ww | sed 's/PasswordField\[/PasswdField:  /' | tr -d ']'
  grep -soP '(WWW-Authenticate\[).*?(?=\])' $temp/ww | sort -u | sed 's/WWW-Authenticate\[/WWW-Auth.:      /' | tr -d ']['
  meta_geo=$(f_getWW_ITEM "meta_geo"); [[ -n "$meta_geo" ]] && echo "Meta Geo:     $meta_geo"
  [[ -n "$ww_other" ]] && echo "$ww_other"
  if [[ $mailcount -gt 0 ]]; then
    [[ $(f_countW "$ww_email") -lt 3 ]] && echo -e "\nEmail:        $print_mail" || echo -e "\n\nEMAIL\n" echo "$print_email" | fmt -w 70
  fi
  if [ -f $temp/sec_headers ] || [ -n "$uncommon" ]; then
    echo ''; f_Medium; echo -e "UNCOMMON & SECURITY HEADERS\n\n"
    [[ -f $temp/sec_headers ]] && cat $temp/sec_headers && echo ''; [[ -n "$uncommon" ]] && echo "$uncommon" | fmt -w 60 | sed G
    [[ -n "$get_cookies" ]] && echo -e "\nCOOKIES\n$get_cookies\n"
  fi
else
  echo -e "\nWhatWeb (hackertarget.com IP tools)  -  Error retrieving results for $x"
fi
}

# ---------------------------------  URLSCAN  -----------------------------------------

f_getURLSCAN(){
local s="$*"
[[ -f $temp/urlscan.json ]] && rm $temp/urlscan.json; [[ -f $temp/urlscan ]] && rm $temp/urlscan
$CURL -s -m 7  "https://urlscan.io/api/v1/search/?q=domain:${s}" > $temp/urlscan.json
if [ -f $temp/urlscan.json ]; then
  $JQ '.results[] | {URL: .task.url, IP: .page.ip, GEO: .page.country, HOST: .page.domain, STATUS: .page.status, SRV: .page.server, DOM: .page.apexDomain, TITLE: .page.title, ASN: .page.asn, ASNAME: .page.asnname, ISSUED: .page.tlsValidFrom, ValidDays: .page.tlsValidDays, Issuer: .page.tlsIssuer, SCR: .screenshot, DATE: .task.time}' $temp/urlscan.json | tr -d '{",}' | sed 's/^[ \t]*//;s/[ \t]*$//' | grep -v 'null' |
  sed -e '/./{H;$!d;}' -e 'x;/IP:/!d;' | sed '/GEO:/a )' | sed '/^TITLE:/i |' | tr '[:space:]' ' ' | sed 's/URL:/\n\nURL:/g' |
  sed 's/^[ \t]*//;s/[ \t]*$//' > $temp/urlscan
fi
}

f_printURLSCAN(){
local i="$*"
if [ -f $temp/urlscan ]; then
  echo ''; grep -siaw $i $temp/urlscan | sed 's/URL:/\n\n\n*/g' | sed 's/IP:/\n\n>/g' | sed 's/^ *//' | sed 's/GEO:/(/g' |
  sed 's/( /(/g' | sed 's/HOST://g' | sed 's/STATUS:/\n\n  Status:/g' | sed 's/SRV:/| Server:/g' | sed 's/DOM:/| Domain:/g' |
  sed 's/ )/)/g' | sed 's/| TITLE:/\n\n  Title: /g' | sed 's/ASN:/\n\n  ASN:   /g' | sed 's/ASNAME:/-/g' |
  sed 's/ISSUED:/\n\n  Cert:   Issued:/g' | sed 's/DATE:/\n\n  Date:  /' | sed 's/ValidDays:/| Valid(days):/g' |
  sed 's/Issuer:/| CA:/g' | sed 's/SCR:/\n\n  SCR:   /g' | sed '/./,$!d'
fi
}

f_URLSCAN_FULL(){
if [ -f $temp/urlscan ]; then
  f_HEADLINE2 "$1  [urlscan.io]  -  $file_date"; v4=$(f_EXTRACT_IP4 "$temp/${1}_ips"); v6=$(f_EXTRACT_IP6 "$temp/${1}_ips")
  echo -e "$1\n"; [[ -n "$v4" ]] && f_printADDR "$v4"; [[ -n "$v6" ]] && f_printADDR "$v6"; echo ''
  cat $temp/urlscan | sed 's/URL:/\n\n\n*/g' | sed 's/IP:/\n\n>/g' | sed 's/^ *//' | sed 's/GEO:/(/g' | sed 's/( /(/g' |
  sed 's/HOST://g' | sed 's/STATUS:/\n\n  Status:/g' | sed 's/SRV:/| Server:/g' | sed 's/DOM:/| Domain:/g' | sed 's/ )/)/g' |
  sed 's/| TITLE:/\n\n  Title: /g' | sed 's/ASN:/\n\n  ASN:   /g' | sed 's/ASNAME:/-/g' |
  sed 's/ISSUED:/\n\n  Cert:   Issued:/g' | sed 's/DATE:/\n\n  Date:  /' |
  sed 's/ValidDays:/| Valid(days):/g' | sed 's/Issuer:/| CA:/g' | sed 's/SCR:/\n\n  SCR:   /g' | sed '/./,$!d'; echo ''
  egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $temp/urlscan |
  sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n -u > $temp/urlscan_ips
  if [ -f $temp/urlscan_ips ]; then
   echo -e "\n"; f_WHOIS_TABLE "$temp/urlscan_ips"; echo ''
  fi
fi
}

f_URLSCAN_DUMP(){
f_getURLSCAN "$1"; f_URLSCAN_FULL "$1" > $temp/uscan_results
[[ -f $temp/uscan_results ]] && cat $temp/uscan_results > ${outdir}/URLSCAN_$1.txt
}

f_URLSCAN_SUBDOMAINS(){
if [ -f $temp/urlscan.json ]; then
  $JQ '.results[] | {P: .task.domain, APEX: .task.apexDomain}?' $temp/urlscan.json | tr -d '{",}' > $temp/uscan_hosts
  $JQ '.results[] | {P: .page.domain, APEX: .page.apexDomain}?' $temp/urlscan.json | tr -d '{",}' >> $temp/uscan_hosts
  domain_name=$(echo "$x" | rev | cut -d '.' -f 2- | rev)
  if [ -f $temp/uscan_hosts ]; then
    sed 's/^[ \t]*//;s/[ \t]*$//' $temp/uscan_hosts | cut -s -d ':' -f 2  | tr -d ' ' | grep -sE "*.$domain_name.*" |
    sort -iu > $temp/uscan_subs
  fi
fi
}

# ---------------------------------  HTTP HEADERS: RETRIEVE & PRINT   -----------------------------------------

f_getHEADERS(){
local s="$*"
if [ $header_source = "3" ] || [ $option_connect = "0" ] ; then
    $CURL -s -m 5 "https://api.hackertarget.com/httpheaders/?q=${s}${api_key_ht}" > $temp/headers
else
    $CURL -sILk -m 10 ${ua} ${s} > $temp/headers
fi
}

f_HEADERS(){
local s="$*"; echo ''; f_HEADLINE "$1  | HTTP HEADERS |  $(date)"; cat $temp/headers | sed 's/^ *//'
}

f_printHEADER_ITEM(){
echo "$1" | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' | sed 's/^ *//' | sed 's/^\=>//' | sed 's/=> /=>/g' |
sed 's/ =>/=>/g' | sed 's/=>/ => /g' | sed 's/^ *//'; echo ''
}

# ---------------------------------  DETECT CDN & INCAPSULA CLOUD WAF  -----------------------------------------


# Detects AWS Cloudfront, Cloudflare, Fastly CDN & Imperva Incapsula WAF
f_detectCDN(){
[[ -f $temp/cdn ]] && rm $temp/cdn
if [[ $(grep -sEioc "cf-ray|cloudflare|cf-cache*"  $temp/http) -gt 0 ]]; then
    echo "CLOUDFLARE" > $temp/cdn
elif [[ $(grep -sEioc "^fastly-.*|x-fastly.-*"  $temp/http) -gt 0 ]]; then
    echo "FASTLY" > $temp/cdn
elif [[ $(grep -sEioc "incap_ses|incapsula|^x-original-uri:|^x-i*nfo:" $temp/http) -gt 0 ]]; then
    echo "IMPERVA_INCAPSULA" > $temp/cdn
elif [[ $(grep -sEioc "originshieldhit|cloudfront-.*|x-amz-cf-id"  $temp/http) -gt 0 ]]; then
    echo "AWS_CLOUDFRONT" > $temp/cdn
fi
}

# Incapsula Imperva FW prevents access to CLI tools not supporting JavaScript
f_IMPERVA(){
[[ -f $temp/cdn ]] || f_detectCDN "$temp/http"
if [ -f $temp/cdn ]; then
  [[ $(grep -sc "IMPERVA_INCAPSULA" $temp/cdn) -gt 0 ]] && echo "true" || echo "false"
else
  echo "false"
fi
}

# --------------------------------- AUTHENTICATION & PROXY HEADERS -----------------------------------------

f_AUTH(){
if [ $option_connect = "0" ] && [ -f $temp/ww ]; then
    f_getWW_ITEM "Proxy-Authenticate"; f_getWW_ITEM "WWW-Authenticate"; f_getWW_ITEM "Proxy-Authorization"
else
    grep -sEi "^Proxy-Authenticate:|^Proxy-Authorization:|WWW-Authenticate:" $temp/headers | tail -1
fi
}

f_PROXY(){
local headers_file="$*"
if [ $option_connect = "0" ] && [ -f $temp/ww ]; then
    f_getWW_ITEM "Via" | tail -1; f_getWW_ITEM "Via-Proxy" | tail -1; f_getWW_ITEM "X-Squid" | tail -1
    f_getWW_ITEM "X-Varnish" | tail -1
else
  grep -sEai "^Via:|^via-proxy:|^X-Squid|^X-Varnish:|^x-pass-why:|x-redirect-by:" $headers_file="$*" | tail -1
fi
}

# ---------------------------------  APPLICATION HEADERS  -----------------------------------------

f_getAPP_HEADERS(){
local headers_file="$*"
[[ -f $temp/app_headers ]] && rm $temp/app_headers
if [ -f $temp/ww ]; then
  grep -sioP 'X-Powered-By\[\K.*?(?=\])' $temp/ww >> $temp/app_headers
  grep -sioP 'X-Generator\[\K.*?(?=\])' $temp/ww >> $temp/app_headers
fi
if [ $option_connect != "0" ]; then
  grep -sEiw "^x-aspnet-version:|^x-aspnetmvc-version:|^x-generator:|^x-powered-by:" $headers_file |
  cut -s -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' >> $temp/app_headers
fi
if [ -f $temp/app_headers ]; then
  app_headers=$(sort -bfiu $temp/app_headers | sed 's/^/,/' | tr '[:space:]' ' ' | sed 's/^\,//' | sed 's/ ,/,/g' |
  sed 's/,/, /g'; echo '')
  [[ -n "$app_headers" ]] && echo "$app_headers"
fi
}

# ---------------------------------  SECURITY HEADERS  -----------------------------------------

f_getSEC_HEADERS(){
local s="$*"; rpol_objects=""; report_objects=""
[[ -f $temp/deprecated ]] && rm $temp/deprecated; [[ -f $temp/headers_other ]] && rm $temp/headers_other
c_pol=$(grep -sEow "^content-security-policy:" ${s}); c_pol_report=$(grep -sEow "^content-security-policy-report-only:" ${s})
if [ -n "$c_pol" ]; then
  cpol_objects=$(grep -sEi "^content-security-policy:" ${s} |
  grep -sEaio "base-uri|block-all-mixed-content|connect-src|default-src|font-src|form-action|frame-ancestors|frame-src|img-src|manifest-src|media-src|object-src|plugin-types|reflected-xss|report-uri|sandbox|script-nonce|script-src" |
  sort -u | tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//'; echo '')
fi
if [ -n "$c_pol_report" ]; then
  report_objects=$(grep -sEi "^content-security-policy-report-only:" ${s} | grep -sEaio "base-uri|block-all-mixed-content|connect-src|default-src|font-src|form-action|frame-ancestors|frame-src|img-src|manifest-src|media-src|object-src|plugin-types|reflected-xss|report-uri|sandbox|script-nonce|script-src" |
  sort -u | tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//'; echo '')
fi
c_control=$(f_printHEADER_ITEM "$(grep -sEw "^cache-control:" ${s} | sed 's/cache-control:/=>/')")
strict_ts=$(f_printHEADER_ITEM "$(grep -sEa "^strict-transport-security:" ${s} | sed 's/strict-transport-security:/=>/g')")
www_auth=$(f_printHEADER_ITEM "$(grep -sEw "^www-authenticate:" ${s} | sed 's/www-authenticate:/=>/g')")
x_frame=$(f_printHEADER_ITEM "$(grep -sEw "^x-frame-options:" ${s} | sed 's/x-frame-options:/=>/')")
p3p=$(grep -sEiw "^p3p:" ${s} | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | tail -1)
x_cross=$(grep -sEw "^x-permitted-cross-domain-policies" ${s} | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | sort -u)
access_origin=$(grep -sEw "^access-control-allow-origin:" ${s} | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | sort -u)
grep -sEoi "e-tag|access-control-allow-.*|access-control-expose-.*|cross-origin-.*" ${s} | grep -wv 'access-control-allow-origin' > $temp/headers_other
grep -sEw "^origin:" ${s} | sed 's/^[ \t]*//;s/[ \t]*$//' | tail -1 >> $temp/headers_other
grep -sEw "^x-ua-compatible:" ${s} | sed 's/^[ \t]*//;s/[ \t]*$//' | tail -1 >> $temp/headers_other
[[ -f $temp/headers_other ]] && [[ $(wc -l < $temp/headers_other) -gt 0 ]] && headers_other=$(cat $temp/headers_other | tr '[:space:]' ' '; echo '')
referrer_pol=$(grep -sEw "^referrer-policy:" ${s} | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | sort -u)
if [ -n "$referrer_pol" ]; then
  if [[ $(f_countL "$referrer_pol") = "1" ]]; then
     ref_pol_value=$(echo "$referrer_pol" | tr '[:space:]' ' '; echo '')
  elif [[ $(f_countL "$referrer_pol") -gt "1" ]]; then
    ref_pol_value=$(grep -sEw "^referrer-policy:" ${s} | sed 's/referrer-policy:/=>/' | sed 's/^[ \t]*//;s/[ \t]*$//' |
    tr '[:space:]' ' ' | sed 's/^ *//' | sed 's/^\=>//')
  else
   ref_pol_value="Empty string"
  fi
fi
grep -sEw "^expect-ct:|^pragma:|^public-key-pins|^x-xss-protection:" ${s} | sort -bifu > $temp/deprecated
grep -siow -m 1 "feature-policy" ${s} >> $temp/deprecated
grep -siow -m 1 "permissions-policy" ${s} >> $temp/deprecated
[[ -n "$referrer_pol" ]] && referrer_pol="*" && rpol_comment="(policy too broad?)"
[[ -n "$strict_ts" ]] && echo -e "Strict-Transport-Security:  $strict_ts" || echo "Strict-Transport-Security" > $temp/missing
[[ -n "$c_pol" ]] || echo -e "Content-Security-Policy:    $c_pol" || echo "Content-Security-Policy" >> $temp/missing
[[ -n "$c_control" ]] && echo -e "Cache-Control:              $c_control" || echo "Cache-Control" >> $temp/missing
[[ -n "$clear_data" ]] && echo -e "Clear-Site-Data:            $clear_data" || echo "Clear-Site-Data" >> $temp/missing
[[ -n "$referrer_pol" ]] && echo -e "Referrer-Policy:            $ref_pol_value  $rpol_comment" || echo "Referrer-Policy" >> $temp/missing
[[ -n "$x_copt" ]] && echo -e "X-Content-Type-Options:     $x_copt"
[[ -n "$x_frame" ]] && echo -e "X-Frame-Options:            $x_frame  (consider replacement with CSP directives)"
[[ -n "$headers_other" ]] && [[ $(f_countW "$headers_other") -lt 3 ]] && echo -e "Other:                      $headers_other"
[[ -n "$cpol_objects" ]] && echo -e "\n\nContent-Security-Policy Objects:\n\n$cpol_objects"
[[ -n "$rep_objects" ]] && echo -e "\n\nContent-Security-Policy-REPORT-ONLY Obj:\n\n$rep_objects"
[[ -n "$access_origin" ]] && echo -e "\nAccess-Control-Allow-Origin:\n\n$access_origin" && aco_count=$(f_countW "$access_origin")
[[ -n "$x_cross" ]] && echo -e "\n\nX-Permitted-Cross-Domain-Policies:\n\n$x_cross"
[[ -n "$p3p" ]] && echo -e "\n\nP3P:\n$p3p"
[[ -n "$headers_other" ]] && [[ $(f_countW "$headers_other") -gt 2 ]] && echo -e "\n\nOther:\n\n$headers_other"
[[ -f $temp/deprecated ]] && [[ $(wc -w < $temp/deprecated) -gt 0 ]] && echo -e "\n\nDeprecated:\n" && cat $temp/deprecated
if [ -f $temp/missing ] && [[ $(wc -w < $temp/missing) -gt 0 ]]; then
  [[ $(wc -w < $temp/missing) -lt 7 ]] && echo ''
  echo -e "\n\nNot set:\n\n"
  print_missing=$(sed 's/^/,/' $temp/missing | tr '[:space:]' ' ' | tr -d ' ' | sed 's/^,//' | sed 's/,/, /g'; echo '')
  echo -e "$print_missing" | fmt -w 60
fi
if [ -f $temp/ww ]; then
  uncomm=$(f_getUNCOMMON_HEADERS); [[ -n "$uncomm" ]] && echo -e "\n\nUncommon Headers:\n\n$uncomm\n"
fi
}

#-------------------------------  DOMAIN STATUS -------------------------------

f_DOMAIN_STATUS(){
f_RESOLVE_ALL "$x" | tee $temp/x_ips > $temp/ips_all
cat $temp/whois_status
if [ $option_connect != "0" ] && [ $webpresence = "true" ]; then
  f_getWEB_INFO "$x"
fi
f_URLSCAN_DUMP "$x"; f_URLSCAN_SUBDOMAINS "$x"
}

f_WHOIS_STATUS(){
[[ -f $temp/whois_tmp ]] && rm $temp/whois_tmp; [[ -f $temp/tmp ]] && rm $temp/tmp
[[ -f $temp/domain ]] && rm $temp/domain; [[ -f $temp/whois_ns ]] && rm $temp/whois_ns
[[ -f $temp/whois_dates ]] && rm $temp/whois_dates; [[ -f $temp/dom_poc ]] && rm $temp/dom_poc
domain_name=""; whois_ns=""
# --- ASK IANA FOR SOURCE ---
iana_info=$(echo "$1" | $NCAT whois.iana.org 43 | grep -sEa "^refer:|^domain:|^organisation:")
tld=$(echo "$iana_info" | grep -m 1 'domain:' | awk '{print $NF}' | tr -d ' ')
if [ $tld = "FR" ]; then
  whois_server="whois.afnic.fr"
else
  whois_server=$(echo "$iana_info" | grep -m 1 'refer:' | awk '{print $NF}' | tr -d ' ')
fi
nic_org=$(echo "$iana_info" | grep -m 1 'organisation:' | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
if [ -n "$whois_server" ]; then
  # ---  GET WHOIS DATA  ---
  if [[ $tld = "JP" ]]; then
    $TOUT 20 $WHOIS -h whois.jprs.jp $1 | sed 's/^ *//' > $temp/whois_tmp
    if [[ $(grep -sEac "\[Expires on\]" $temp/whois_tmp) -eq 0 ]]; then
      timeout 20 $WHOIS -h whois.jprs.jp ${whois_query}/e | sed 's/^ *//' > $temp/whois_tmp
    fi
    domain_name=$(grep -E "^\[Domain Name\]" $temp/whois_tmp | cut -d ']' -f 2- | sed 's/^ *//' | tr [:upper:] [:lower:])
    [[ -n "$domain_name" ]] && cat $temp/whois_tmp > $temp/domain
  elif echo $whois_server | grep -q -E "whois\.denic\.de"; then
    $TOUT 20 $WHOIS -h whois.denic.de -- "-T dn $1" | sed '/^%/d' | sed 's/^ *//' | sed '/^$/d' > $temp/whois_tmp
    domain_name=$(grep -E "^Domain:" $temp/whois_tmp | awk '{print $NF}' | tr [:upper:] [:lower:] | head -1 | tr -d ' ')
    whois_ns=$(grep -sEai "^Nserver:" $temp/whois_tmp | cut -d ':' -f 2- | awk '{print $1}' | tr -d ' ')
    [[ -n "$domain_name" ]] && cat $temp/whois_tmp > $temp/domain
  else
    $TOUT 30 $WHOIS -h $whois_server $1 | sed '/please/d' | sed '/%/d' | sed '/REDACTED/d' |
    sed '/for more/d' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' | tee $temp/tmp > $temp/whois_tmp
    if echo $whois_server | grep -q -E "whois\.nic\.uk"; then
      domain_name=$(grep -sE "^Domain name:" $temp/whois_tmp | tail -1 | grep -sEoi "$HOSTNAME_ALT")
    else
      registrar_server=$(grep -sE "^Registrar WHOIS Server:" $temp/whois_tmp | cut -d '/' -f 1 | grep -sEoi "$HOSTNAME_ALT")
      if [ -n "$registrar_server" ]; then
        $WHOIS -h "$registrar_server" $1 | sed '/please/d' | sed '/%/d' | sed '/REDACTED/d' | sed '/for more/d' |
        sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' > $temp/tmp
        registrar_response=$(grep -sEia "^Domain Name:|^Domain:" $temp/tmp | cut -s -d ':' -f 2- | grep -sEoi -m 1 "$HOSTNAME_ALT")
        [[ -n "$registrar_response" ]] && cat $temp/tmp > $temp/whois_tmp
      fi
      domain_name=$(grep -sEia "^Domain Name:|^Domain:"  $temp/whois_tmp | cut -s -d ':' -f 2- |
      tr [:upper:] [:lower:] | grep -sEoi -m 1 "$HOSTNAME_ALT")
    fi
    if [[ $(grep -Eoc "^Domain Name:" $temp/tmp) -gt 1 ]]; then
      sed -n '/Domain Name:/,/Domain Name:/p' $temp/whois_tmp > $temp/domain
    else
      cat $temp/whois_tmp > $temp/domain
    fi
  fi
  if [ -f $temp/domain ]; then
    # --- Why it can't be a simple grep 'Domain:' is beyond me ---
    dnssec=$(grep -sEai "^DNSSEC:" $temp/domain | cut -d ':' -f 2- | sed 's/^ *//')
    if echo $whois_server | grep -q -E "whois\.jprs\.jp"; then
      whois_ns=$(grep -sEiw "\[Name Server\]" $temp/domain | cut -d ']' -f 2 | sed 's/^ *//' | cut -d ' ' -f 1)
      dstate=$(grep -E "^\[State\]" $temp/domain | cut -d ']' -f 2- | sed 's/^ *//')
      upd=$(grep -E "^\[Last Updated\]" $temp/domain | cut -d ']' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | cut -d ' ' -f 1)
      ex=$(grep -E "^\[Expires on\]" $temp/domain | cut -d ']' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | cut -d ' ' -f 1)
      cr=$(grep -E "^\[Created on\]" $temp/domain | cut -d ']' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | cut -d ' ' -f 1)
      reg_name=$(grep -sEa "^\[Registrant\]" $temp/domain | cut -d ']' -f 2- | sed 's/^ *//')
      reg_org=$(grep -sEa -A 3 "Contact Information:" $temp/domain | grep -sEa "^\[Name\]" | cut -d ']' -f 2- | sed 's/^ *//')
      whois_ns=$(grep -sEa "\[Name Server\]" $temp/domain | cut -d ']' -f 2- | grep -sEoi "$HOSTNAME_ALT")
    elif echo $whois_server | grep -q -E "whois\.nic\.uk"; then
      whois_ns=$(sed -n '/Name servers:/,/Copyright Nominet/p' $temp/domain | grep -sEoi "$HOSTNAME_ALT")
      registrar=$(grep -A 1 'Registrar:' $temp/domain | tail -1 | sed 's/^[ \t]*//;s/[ \t]*$//')
      dstatus=$(grep -sE -A1 "^Registration status:" $temp/domain | tail -1 | sed 's/^[ \t]*//;s/[ \t]*$//')
      rel_dates=$(sed -n '/Relevant dates:/,/Registration status:/p' $temp/domain)
      ex=$(echo "$rel_dates" | grep 'Expiry' | cut -d ':' -f 2- |  sed 's/^[ \t]*//;s/[ \t]*$//')
      upd=$(echo "$rel_dates" | grep 'updated:' | cut -d ':' -f 2- |  sed 's/^[ \t]*//;s/[ \t]*$//')
      cr=$(echo "$rel_dates" | grep 'Registered on:' | cut -d ':' -f 2- |  sed 's/^[ \t]*//;s/[ \t]*$//')
    else
      dstatus=$(f_VALUE ":" "$(grep -sEai -m 1 "^Status:|^Domain Status:|^Registration Status:" $temp/domain)" |
      awk -F'https://icann.org' '{print $1}')
      dstate=$(f_VALUE ":" "$(grep -sa -m 1 '^state:' $temp/domain)" | awk -F'https://icann.org' '{print $1}')
      hold=$(f_VALUE ":" "$(grep -saiw -m 1 '^hold' $temp/domain)")
      reg_lock=$(f_VALUE ":" "$(grep -sai -m 1 '^registry-lock:' $temp/domain)")
      cr=$(f_VALUE ":" "$(grep -sEai -m 1 "^Creation Date:|Created:|Registration Date:|^Registered" $temp/domain)" | cut -d 'T' -f 1)
      upd=$(f_VALUE ":" "$(grep -sEai "^last-update:|^Updated Date:|^Updated" $temp/domain)" | head -1 | cut -d 'T' -f 1)
      changd=$(f_VALUE ":" "$(grep -sai '^Changed:' $temp/domain)" | head -1 | cut -d 'T' -f 1)
      trans=$(f_VALUE ":" "$(grep -sai '^transferred:' $temp/domain)" | head -1 | cut -d 'T' -f 1)
      modif=$(f_VALUE ":" "$(grep -sEai "^modified:|^last modified" $temp/domain)" | head -1 | cut -d 'T' -f 1)
      country=$(f_VALUE ":" "$(grep -sEai -m 1 "^Registrant Country:|^Country:" $temp/domain)")
      registrar=$(f_VALUE ":" "$(grep -sEai "^Registrar:|^Registrar Name:" $temp/domain)" | head -1)
      if [[ $(grep -woic "^REGISTRAR:" $temp/domain) -gt 0 ]] && [ -z "$registrar" ]; then
        registrar=$(f_VALUE ":" "$(grep -sai -m 1 -A 1 '^REGISTRAR:' $temp/domain)" | tail -1)
      fi
      if echo $whois_server | grep -q -E "whois\.nic\.fr"; then
        reg_name=$(f_VALUE ":" "$(grep -sa '^contact:' $temp/domain)" | grep -sEai -v "$registrar" | head -1)
      else
        reg_name=$(f_VALUE ":" "$(grep -sEai -m 1 "^Registrant:|^Registrant Name:|^owner:" $temp/domain)")
        reg_org=$(f_VALUE ":" "$(grep -sEai -m 1 "^Registrant Organization:|Organisation:|^Company Name:|^org:" $temp/domain)")
      fi
      if [ -z "$reg_name" ] && [ -z "$reg_org" ] && [[ $(grep -woic "^REGISTRANT:" $temp/domain) -gt 0 ]]; then
        reg_name=$(f_VALUE ":" "$(grep -sai -m 1 -A 1 '^REGISTRANT:' $temp/domain)" | tail -1)
      fi
      reg_type=$(f_VALUE ":" "$(grep -sEai -m 1 "^typ:|^registrant type:" $temp/domain)")
      holder=$(f_VALUE ":" "$(grep -saiw -m 1 '^holder:' $temp/domain)")
      pers=$(f_VALUE ":" "$(grep -sai -m 1 'person:' $temp/domain)")
      chin_name=$(f_VALUE ":" "$(grep -sai '^Company chinese name:' $temp/domain)" | head -1)
      owner_c=$(f_VALUE ":" "$(grep -sai -m 1 '^owner-c:' $temp/domain)")
      responsible=$(f_VALUE ":" "$(grep -sai '^responsible:' $temp/domain)")
      admin_c=$(grep -sEia -A 2 "^admin-c:|^admin:|^administrator:" $temp/domain | grep -sEai "^role:|^nic-hdl:" |
      cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' '; echo '')
      role_c=$(grep -sEia -A 2 "^role:" $temp/domain | grep -sEai "^role:|^nic-hdl:" | cut -d ':' -f 2- |
      sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' '; echo '')
      epp_status=$(grep -sEai -A 10 "^domain:" $temp/domain | grep -sEa "^eppstatus:"  | cut -d ':' -f 2 |
      sed 's/^[ \t]*//;s/[ \t]*$//' | sort -u | tr '[:space:]' ' '; echo '');
    fi  # get data from different response formats
    # NS
    if [ -z "$whois_ns" ]; then
      if echo $whois_server | grep -q -E "whois\.verisign-grs\.com"; then
        whois_ns=$(grep -sEai "^Name Server:" $temp/domain | awk '{print $NF}' | tr [:upper:] [:lower:])
      else
        whois_ns=$(grep -sEaiw "^Name Server:|^Nserver:" $temp/domain | grep -sEoi "$HOSTNAME_ALT")
      fi
    fi
    if [ -z "$whois_ns" ]; then
      whois_ns=$(grep -sEai -A 10 "NAMESERVERS|Name Servers|^nameservers:" $temp/domain | grep -sEoi "$HOSTNAME_ALT")
    fi
    if [ -n "$whois_ns" ]; then
      ns_sorted=$(echo "$whois_ns" | tr [:upper:] [:lower:] | grep -sEo "\b[a-zA-Z0-9._-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,5}\b" | sort -uV)
    fi
    # PoC
    f_EXTRACT_EMAIL "$temp/domain" > $temp/dom_poc; grep -sEai "\[Phone\]|phone:" $temp/domain | cut -d ':' -f 2- |
    cut -d ']' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | tr -d ' ' | sort -u >> $temp/dom_poc
    [[ -f $temp/dom_poc ]] && whois_contact=$(sed 's/^[ \t]*//;s/[ \t]*$//' $temp/dom_poc | tr '[:space:]' ' ' | fmt -w 80; echo '')
    [[ -n "$cr" ]] && echo "Created:$cr" >> $temp/whois_dates; [[ -n "$ex" ]] && echo "Expires:$ex" >> $temp/whois_dates
    [[ -n "$pd" ]] && echo "Paid_until:$pd" >> $temp/whois_dates; [[ -n "$changd" ]] && echo "Changed:$changd" >> $temp/whois_dates
    [[ -n "$upd" ]] && echo "Updated:$upd" >> $temp/whois_dates; [[ -n "$modif" ]] && echo "Modified:$modif" >> $temp/whois_dates
    [[ -n "$dfree" ]] && echo "Free:$dfree" >> $temp/whois_dates; [[ -n "$trans" ]] && echo "Transferred:$trans" >> $temp/whois_dates
    # Dates
    if [ -f $temp/whois_dates ]; then
      whois_dates=$(cat $temp/whois_dates | sed '/^$/d' |  tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/ /  /g' |
      sed 's/_/ /g' | sed 's/:/: /g' | sed 's/^ *//')
    fi
    # Print whois data (target_type = "web)
    if [ $target_type = "web" ]; then
      print_ns=$(echo "$whois_ns" | tr '[:space:]' ' '; echo '')
      f_Long; echo "Domain:          $domain_name"
      [[ $(grep -Eoc "^Domain Status:" $temp/domain) -lt 4 ]] && echo "Status:          $dstatus"
      echo "Dates:           $whois_dates"
      [[ $(f_countW "$whois_ns") -lt 6 ]] && echo "Nservers:        $print_ns"
      [[ $(grep -Eoc "^Domain Status:" $temp/domain) -gt 3 ]] && echo -e "\nSTATUS\n\n$dstatus" | fmt -s -w 60
      [[ $(f_countW "$whois_ns") -gt 5 ]] && echo -e "\nNSERVERS:\n\n$print_ns" | fmt -s -w 60
    else #  target_type != web
      [[ $target_type = "whois_target" ]] && f_HEADLINE2 "$(f_toUPPER $domain_name)"
      [[ $target_type = "dnsrec" ]] && echo -e "\nWHOIS STATUS\n"
      echo -e "\nDomain:      $domain_name\n"
      [[ -n "$dstatus" ]] && [[ $(grep -Eoc "^Domain Status:" $temp/domain) -lt 2 ]] && echo "Status:      $dstatus"
      [[ -n "$dstate" ]] && echo "State:       $dstate"; [[ -n "$dhold" ]] && echo "Hold:        $hold"
      [[ -n "$reg_lock" ]] && echo "Reg.-Lock:   $reg_lock"; [[ -n "$dnssec" ]] && echo "Dnssec:      $dnssec"
      [[ -n "$whois_dates" ]] && echo "Dates:       $whois_dates"; [[ -n "$epp_status" ]] && echo "EPP Status:  $epp_status"
      [[ -n "$reg_name" ]] || [[ -n "$reg_org" ]] && echo ''
      [[ -n "$reg_name" ]] && echo "Registrant:  $reg_name"; [[ -n "$reg_org" ]] && echo "Org:         $reg_org $chin_name $owner_c"
      [[ -n "$country" ]] && echo "Country:     $country";  [[ -n "$reg_type" ]] && echo "Type:        $reg_type"
      [[ -n "$pers" ]] && echo "Person:      $pers"; [[ -n "$holder" ]] && echo "Holder:      $holder"
      [[ -n "$responsible" ]] && echo "Responsible: $responsible"; [[ -n "$admin_c" ]] && echo "Admin:       $admin_c"
      [[ -n "$role_c" ]] && echo "Role:        $role_c"; [[ -n "$registrar" ]] && echo "Registrar:   $registrar"
      echo "Source:      $whois_server ($nic_org)"
      [[ -n "$registrar_server" ]] && echo "Server:      $registrar_server"
      contacts_count=$(f_countW "$whois_contact")
      if [ $target_type != "web" ] && [ $target_type != "whois_target" ]; then 
        print_ns=$(echo "$whois_ns" | tr '[:space:]' ' '; echo '')
        if [[ $contacts_count -gt 0 ]]; then
          [[ $contacts_count -lt 4 ]] && echo "Contact:     $whois_contact"
        fi 
        [[ -n "$print_ns" ]] && echo -e "\nNservers:    $print_ns" || echo "Nservers:    please double check whois results manually"
      else
        if [[ $contacts_count -gt 0 ]]; then
          [[ $contacts_count -lt 4 ]] && echo "Contact:     $whois_contact"
        fi 
      fi 
      if [ $contacts_count -gt 3 ]; then
        echo -e "\n\nCONTACT\n" && echo -e "$whois_contact" | sed 's/ /  /g' | sed G | sed -e :a -e '/^\n*$/{$d;N;ba' -e '}'
      fi
      if [[ $(grep -Eoc "^Domain Status:" $temp/domain) -gt 1 ]]; then
        echo -e "\n\nDOMAIN STATUS\n"
        domain_status=$(grep -E "^Domain Status:" $temp/domain | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | awk '{print $1}' | sort -u |
        tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -s -w 75)
        if [ $target_type = "whois_target" ]; then
          echo "$domain_status" | sed G | sed -e :a -e '/^\n*$/{$d;N;ba' -e '}'
        else
          echo -e "$domain_status\n"
        fi
      fi
      if [ $target_type = "whois_target" ]; then
        echo -e "\n\nNAME SERVERS\n"
        if [ -n "$ns_sorted" ]; then
          ns_sorted=$(echo "$whois_ns" | tr [:upper:] [:lower:] | grep -sEo "\b[a-zA-Z0-9._-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,5}\b" | sort -uV)
          echo "$ns_sorted" > $temp/whois_ns; print_whois_ns=$(echo "$ns_sorted" | tr '[:space:]' ' ' | sed 's/ /  /g'; echo '')
          echo -e "$print_whois_ns\n"
        fi
      fi # domain_enum = fale
    fi  #  target_type = web ?
    if [ $target_type = "whois_target" ]; then
      ns_soa=$($DIG soa +short $domain_name | awk '{print $1,$2," Serial:",$3}')
      echo -e "\nSOA\n\n$ns_soa\n"
      echo -e "\nHOSTS\n"
      print4=$(f_printADDR "$($DIG +short $domain_name  | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')")
      print6=$(f_printADDR "$($DIG aaaa +short $domain_name  | grep ':' | sort -u)")
      [[ -n "$print4" ]] && echo -e "$print4" | sed 's/ /  /g' | sed G | tee -a "$temp/domains_ipv4"
      [[ -n "$print6" ]] && echo -e "$print6" | sed 's/ /  /g' | sed G
    fi
  else
    echo -e "\nERROR getting whois results for $whois_query\n";
  fi
else
  echo -e "\nERROR - Whois: Invalid domain or host name supplied\n"
fi
}

f_SUBS(){
$CURL -s -m 30 https://api.hackertarget.com/hostsearch/?q=$1${api_key_ht} | grep -sE "$IP4_ALT" > $temp/ht_raw
if [ -f $temp/ht_raw ] && [[ $(wc -l < $temp/ht_raw) -gt 2 ]]; then
  grep ',' $temp/ht_raw | sort -u | tee $temp/subs_tmp > $temp/results_ht
  cut -d ',' -f 1 $temp/results_ht | sort -u > $temp/hosts_raw
  sort -t ',' -k 1 $temp/results_ht | sed 's/,/ => /' | awk '{print $3 "\t\t" $2 "\t" $1}' > $temp/subs_ht
  f_HEADLINE "$1  SUBDOMAINS (IPV4) | $file_date  [Source: hackertarget.com]" > ${outdir}/Subdomains_HT.${1}.txt
  echo '' >> ${outdir}/Subdomains_HT.${1}.txt; cat $temp/subs_ht >> ${outdir}/Subdomains_HT.${1}.txt
fi
$CURL -sL -m 20 "https://otx.alienvault.com/api/v1/indicators/domain/${1}/passive_dns" > $temp/otx_dns.json
if [ -f $temp/otx_dns.json ]; then
  $JQ '.passive_dns[] | {ADDR: .address, HOSTNAME: .hostname}?' $temp/otx_dns.json | tr -d '{}",' |
  sed 's/^[ \t]*//;s/[ \t]*$//' | grep ':' | tr '[:space:]' ' ' | sed 's/ADDR: /\n/g' | grep -sEa "$IP4_ALT" |
  sed 's/HOSTNAME:/,/' | awk '{print $3 $2 $1}' | sort -u >> $temp/subs_tmp
  [[ -f $temp/subs_tmp ]] && cut -d ',' -f 1 $temp/subs_tmp | sort -u >> $temp/hosts_raw
fi
$CURL -s -m 10 "https://rapiddns.io/subdomain/$1?full=1#result" | grep -sioP '<td>\K.*?(?=</td>)' | grep -v 'href' |
grep -sEo "\b[a-zA-Z0-9._-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,5}\b" | sort -u >> $temp/hosts_raw
[[ -f $temp/uscan_subs ]] && cat $temp/uscan_subs >> $temp/hosts_raw
[[ -f $temp/dnsnames ]] && cat $temp/dnsnames >> $temp/hosts_raw
f_EXTRACT_HOSTN "$(sort -u $temp/hosts_raw)" > $temp/hosts
if [ -f $temp/hosts ]; then
  f_HEADLINE "$1  SUBDOMAINS (IPV4),  $file_date" > $temp/print_subs; echo '' > $temp/subdomains_$1
  f_RESOLVE_SUBS > $temp/subs; [[ -f $temp/subs ]] && cat $temp/subs | tee $temp/subdomains_$1 >> $temp/subdomains_all
  f_EXTRACT_IP4 "$temp/subs" | tee -a $temp/subdomain_ips >> $temp/ips.list
  if [ -f $temp/subdomains_$1 ]; then
    f_HEADLINE3 "[SUBDOMAINS]   $1   (IPv4)  -  $file_date" > ${outdir}/SUBDOMAINS_${1}.txt
    [[ -f $temp/subdomains_$1 ]] && cat $temp/subdomains_$1 >> ${outdir}/SUBDOMAINS_${1}.txt 
  fi
fi
}

f_RESOLVE_SUBS(){
[[ -f $temp/listed_by_ip ]] && rm $temp/listed_by_ip
$NMAP -iL $temp/hosts -sn -Pn -sL -R $nmap_ns 2>/dev/null > $temp/resolved_raw
grep -E "scan report|^Other addresses" $temp/resolved_raw | sed 's/Nmap scan report for //' |
sed 's/Other addresses for //' | sed 's/(not scanned)://' | tr -d '()' | sed 's/^[ \t]*//;s/[ \t]*$//' > $temp/resolved
list_hosts4=$(f_EXTRACT_IP4 "$temp/resolved"); echo "$list_hosts4" >> $temp/ips.list
list_hosts6=$(f_EXTRACT_IP6 "$temp/resolved")
list_hostnames=$(f_EXTRACT_HOSTN "$temp/resolved")
for i4 in $list_hosts4; do
  i4_results=$(grep -w "$i4" $temp/resolved)
  names=$(f_EXTRACT_HOSTN "$i4_results"); names_count=$(f_countW "$names")
  if [[ $names_count -gt 2 ]]; then
    echo "$i4" >> $temp/multiple_hostnames
    echo "$names" >> $temp/listed_by_ip
    print_names=$(echo "$names" | tr '[:space:]' ' ' | sed 's/ /  /g'; echo '')
    echo -e "\n$i4\n\n  ->  $print_names\n" | fmt -w 100
  fi
done > $temp/sublist1
for hn in $list_hostnames; do
  if [[ $(grep -w -c "$hn" $temp/listed_by_ip) -eq 0 ]]; then
    hn_results=$(grep -w "$hn" $temp/resolved)
    h4=$(f_EXTRACT_IP4 "$hn_results")
    print_h4=$(echo "$h4" | tr '[:space:]' ' ' | sed 's/ /  /g'; echo '')
    [[ $h6_count -gt 0 ]] && print_h6=$(echo "$h4" | tr '[:space:]' ' ' | sed 's/ /  /g'; echo '')
    echo -e "\n$hn\n\n  ->  $print_h4\n" | fmt -w 100
  fi
done > $temp/sublist2
[[ -f $temp/sublist2 ]] && cat $temp/sublist2
[[ -f $temp/sublist1 ]] && echo '' && cat $temp/sublist1
}

f_SUBS_HEADER(){
echo -e "\n"
if [[ $option_webdomain = "y" ]]; then
  f_HEADLINE3 "[SUBDOMAINS]   HOSTS, NETWORKS & ORGANISATIONS  ($x, $webdomain)"
else
  f_HEADLINE3 "[SUBDOMAINS]   HOSTS, NETWORKS & ORGANISATIONS  ($x)"
fi 
echo -e "\nSearching for hosts/subdomains...\n"; f_SUBS "$x"
if [[ $option_webdomain = "y" ]]; then
  f_URLSCAN_SUBDOMAINS "$webdomain"; f_SUBS "$webdomain"
fi
[[ -f $temp/subdomains_all ]] && cat $temp/subdomains_all >>  $temp/print_subs
[[ -f $temp/geo_all ]] && cat $temp/geo_all >> $temp/print_subs
subcount=$(f_countL "$(sort -uV $temp/ips.list)")
echo -e "\nFound $subcount unique IPv4 hosts within the following resources:\n\n"
sort -t . -k 1,1n -k 2,2n -k 3,3n -u $temp/ips.list > $temp/ips_sorted.list; f_WHOIS_TABLE "$temp/ips_sorted.list" > $temp/whois_table_tmp
if [ -f $temp/whois_table.txt ]; then
  grep -E "^[0-9]" $temp/whois_table.txt | grep -w -v 'NA' | sed '/^$/d' | sort -t . -k 1,1n -k 2,2n -u > $temp/table_sorted1
  grep -E "^[0-9]" $temp/whois_table.txt | grep -w -v 'NA' | sed '/^$/d' | sort -t '|' -k 5 -u >> $temp/table_sorted1
  cat $temp/table_sorted1 | awk -F '|' '{print $1,$3,$4,$5,$2}' OFS='|' | rev | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n -u |
  cut -d '.' -f 3- | rev | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/$/.x.x/g' | sort -t '|' -k 4 -V > $temp/whois_table2
  grep -E "^[0-9]" $temp/whois_table.txt | grep -w 'NA' | sort -t . -k 1,1n -k 2,2n -u >> $temp/table_sorted11
  cat $temp/table_sorted11 | awk -F '|' '{print $1,$3,$4,$5,$2}' OFS='|' | rev | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n -u |
  cut -d '.' -f 3- | rev | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/$/.x.x/g' | sort -t '|' -k 4 -V >> $temp/whois_table2
fi
if [ -f $temp/whois_table2 ]; then
  cut -d '|' -f -2 $temp/whois_table.txt | grep -E "^[0-9]" | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' |
  sort -uV > $temp/ips_sorted2.list; f_pwhoisBULK "$temp/ips_sorted2.list"
  cut -d '|' -f -2 $temp/whois_table.txt | grep -E "^NA" | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' |
  sort -uV > $temp/no_as.list
  asnums=$(cut -d '|' -f 1 $temp/whois_table2 | tr -d ' ' | sed '/^$/d' | sort -ug)
  grep 'ORG NAME' $temp/whois_table.txt | awk -F '|' '{print $1,$3,$4,$5,$2}' OFS='|'; echo ''; cat $temp/whois_table2
  if [ -f $temp/no_as.list ]; then
    for n in $(cat $temp/no_as.list); do
      f_BOGON "$n"
      [[ $bogon = "TRUE" ]] && echo $n >> $temp/bogons || echo $n >> $temp/v4_no_as
    done
    if [ -f $temp/bogons ]; then
      echo ''; f_Long; echo -e "IPv4 BOGONS\n\n"
      for b in $(cat $temp/bogons | sort -uV); do grep -w "${b}" $temp/resolved; echo "$bogon_sub"; done; echo ''
    fi
    if [ -f $temp/v4_no_as ]; then
      echo -e "\nNOT ANNOUNCED\n"
      cat $temp/v4_no_as | sed 's/^[ \t]*//;s/[ \t]*$//' | sed G | fmt -w 55
    fi
  fi
  f_HEADLINE3 "[PROVIDERS]  AUTONOMOUS SYSTEMS"
  for as in $asnums; do echo ''; f_AS_SHORT "${as}"; done
  if [ -f $temp/lacnic_asns ]; then
    lacnic_asns=$(sort -ug $temp/lacnic_asns | sed 's/^/|/' | tr '[:space:]' ' ' | sed 's/^|//' | grep '|' | tr -d ' ')
    if [ -n "$lacnic_asns" ]; then
      grep -E -v "$lacnic_asns" $temp/pwhois | grep '|' | awk -F '|' '{print $1,$3,$5}' OFS='|' |
      sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n | sort -t '|' -k 3 -V | sed '/^$/d' > $temp/net_table
      grep -E "$lacnic_asns" $temp/pwhois | awk -F'|' '{print $3,"~",$4}' | sed 's/^ *//' |
      sort -t '~' -k 1 -u | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n -u > $temp/lacnic_nets
      f_EXTRACT_IP4 "$(sort -t '~' -k 2 -u $temp/lacnic_nets | cut -s -d '~' -f 1)" > $temp/poc_lookups
    fi
  else
    grep '|' $temp/pwhois | awk -F '|' '{print $1,$3,$5}' OFS='|' | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n |
    sort -t '|' -k 3 -V | sed '/^$/d' > $temp/net_table
  fi
  grep -w -v 'NA' $temp/net_table | cut -s -d '|' -f 3 | sed 's/^[ \t]*//;s/[ \t]*$//' | sort -uV > $temp/nets_uniq
  grep -w 'NA' $temp/pwhois | cut -s -d '|' -f 3 > $temp/no_netname
  for t in $(cat $temp/nets_uniq); do
    grep -E -w ${t} $temp/net_table | cut -d '|' -f 1 | grep -sEo "$IP4_ALT" | head -1
  done > $temp/net_lookup.list
  f_EXTRACT_IP4 "$temp/no_netname" >> $temp/net_lookup.list
fi
}

#-------------------------------  AUTONOMOUS SYSTEMS  -------------------------------

f_AS_INFO(){
option_detail="2"; query_status=""; as_set=""; echo ''
$CURL -s -m 20 --location --request GET "https://stat.ripe.net/data/as-overview/data.json?resource=$1" > $temp/asov.json
as_status=$($JQ '.data.announced' $temp/asov.json | sed 's/true/Active/' | sed 's/false/Inactive/')
$DIG +short as$1.asn.cymru.com TXT | tr -d '"' | sed 's/^[ \t]*//;s/[ \t]*$//' > $temp/cyas
as_rir=$(cut -s -d '|' -f 3 $temp/cyas | sed 's/^[ \t]*//;s/[ \t]*$//'); export rir=$(echo "$as_rir" | sed 's/ripencc/ripe/')
print_rir=$(f_toUPPER "$(echo $as_rir | sed 's/ripencc/ripe ncc/')"); as_cc=$(cut -s -d '|' -f 2 $temp/cyas | tr -d ' ')
alloc_date=$(cut -s -d '|' -f 4 $temp/cyas | sed 's/^[ \t]*//;s/[ \t]*$//' | cut -d '-' -f -2)
spamhaus_listed=$(grep -sw "$1" ${file_date}.asndrop.list)
[[ -n "$spamhaus_listed" ]] && spamhaus_comment=$(grep -w "$1" ${file_date}.asndrop.txt)
if [ $rir = "arin" ] ; then
  timeout 20 $WHOIS -h whois.arin.net a $1 > $temp/whois
  as_number=$(grep -E "^ASNumber:" $temp/whois | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
elif [ $rir = "lacnic" ] ; then
  timeout 20 $WHOIS -h whois.lacnic.net as$1 > $temp/whois
else
  timeout 20 $WHOIS -h whois.$rir.net -- "-B as$1" > $temp/whois
fi
peering_contact=$(f_EXTRACT_EMAIL $(grep -A 1 -sEi "peering|peering requests|policy:" $temp/whois))
[[ -n "$peering_contact" ]] && print_peering_contact=$(echo "| Contact: $peering_contact" | tr '[:space:]' ' '; echo '')
if [ $rir = "lacnic" ]; then
  as_abuse=$(f_printLACNIC_ABUSE_C "$temp/whois")
else
  as_abuse=$(grep -sEa "^OrgAbuseEmail:|^% Abuse|^abuse-mailbox:" $temp/whois | grep -sEao "$REGEX_MAIL" |
  sort -u | tr '[:space:]' ' ' ; echo '')
fi
if [ -z "$as_abuse" ] && [ $rir != "lacnic" ]; then
  $CURL -s -m 20 --location --request GET "https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=$1" > $temp/ac.json
  as_abuse=$($JQ '.data.abuse_contacts[]?' $temp/ac.json | tr '[:space:]' ' '; echo '')
fi
$CURL -s -m 20 --location --request GET "https://stat.ripe.net/data/as-routing-consistency/data.json?resource=$1" > $temp/cons.json
[[ -f $temp/cons.json ]] && pfx_total=$($JQ '.data.prefixes[].prefix?' $temp/cons.json | wc -w) || pfx_total="0"
$CURL -s -m 15 --location --request GET "https://stat.ripe.net/data/ris-prefixes/data.json?resource=${1}&list_prefixes=true&types=t" > $temp/transit.json
$CURL -s -m 10 --location --request GET "https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS$1" > $temp/nb.json
pfx_data=$(jq -r '.data.prefixes[] | {PFX: .prefix, RIS: .in_bgp, WHOIS: .in_whois, IRR: .irr_sources[]}' $temp/cons.json | tr -d '{",}' |
sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d'| tr '[:space:]' ' ' | sed 's/PFX: /\n\n/g'| sed 's/RIS:/| RIS:/' | sed 's/WHOIS:/| WHOIS:/' |
sed 's/IRR:/| IRR:/' | sed 's/| IRR:/| RIR:/' | sed 's/IRR: //g'; echo '')
pfx_total=$(echo "$pfx_data" | grep -c '/')
pfx4_data=$(echo "$pfx_data" | grep -sE "$IP4_NET_ALT"); pfx6_data=$(echo "$pfx_data" | grep -sE "$REGEX_NET6")
v4_all_count=$(echo "$pfx4_data" | grep -c '/'); v6_all_count=$(echo "$pfx6_data" | grep -c '/')
v4_whois_true=$(echo "$pfx4_data" | grep -sc 'WHOIS: true'); v6_whois_true=$(echo "$pfx6_data" | grep -sc 'WHOIS: true')
v4_rirs=$(echo "$pfx4_data" | grep -sEo "AFRINIC|APNIC|ARIN|LACNIC|RIPE" | sort -u | tr '[:space:]' ' '; echo '')
v4_bgp_count=$(echo "$pfx4_data" | grep -sc 'RIS: true'); v6_bgp_count=$(echo "$pfx6_data" | grep -sc 'RIS: true')
v4_low_count=$(echo "$pfx4_data" | grep -sc 'RIS: false'); v6_low_count=$(echo "$pfx6_data" | grep -sc 'RIS: false')
v4_bgp=$(echo "$pfx4_data" | grep -s 'RIS: true' | awk '{print $1}' | tr -d ' ')
v6_bgp=$(echo "$pfx6_data" | grep -s 'RIS: true' | awk '{print $1}' | tr -d ' ')
v4_low_vis=$(echo "$pfx4_data" | grep -s 'RIS: false' | awk '{print $1}' | tr -d ' ')
v6_low_vis=$(echo "$pfx6_data" | grep -s 'RIS: false' | awk '{print $1}' | tr -d ' ')
nbc_uniq=$($JQ '.data.neighbour_counts.unique' $temp/nb.json); nbc_left=$($JQ '.data.neighbour_counts.left' $temp/nb.json)
nbc_right=$($JQ '.data.neighbour_counts.right' $temp/nb.json); nbc_unc=$($JQ '.data.neighbour_counts.uncertain' $temp/nb.json)
nb_right=$($JQ '.data.neighbours[] | select(.type == "right") | .asn' $temp/nb.json | sort -g)
nb_left=$($JQ '.data.neighbours[] | select(.type == "left") | .asn' $temp/nb.json | sort -g)
nb_uncertain=$($JQ '.data.neighbours[] | select(.type == "uncertain") | .asn' $temp/nb.json | sort -g)
transiting=$($JQ '.data.prefixes.v4.transiting[]' $temp/transit.json)
trans4_count=$($JQ '.data.counts.v4.transiting' $temp/transit.json)
trans6_count=$($JQ '.data.counts.v6.transiting' $temp/transit.json)
transiting_aslookups=$(echo "$transiting" | sort -t . -k 1,1n -u)
if [ $as_status = "Active" ]; then
  $CURL -s -m 20 "https://www.peeringdb.com/api/net?asn__in=$1" > $temp/peeringdb_asn.json
  object_id=$($JQ '.data[].id?' $temp/peeringdb_asn.json)
  [[ -n "$object_id" ]] && peering_db_results="true" || peering_db_results="false"
else
  peering_db_results="false"
fi
if [ $peering_db_results = "true" ]; then
  irr_as_set=$($JQ '.data[].irr_as_set' $temp/peeringdb_asn.json | sed '/null/d')
  as_aka=$($JQ '.data[].aka' $temp/peeringdb_asn.json | sed '/null/d')
  as_type=$($JQ '.data[].info_type?' $temp/peeringdb_asn.json | sed '/null/d')
  traffic_volume=$($JQ '.data[].info_traffic' $temp/peeringdb_asn.json | sed '/null/d')
  traffic_ratio=$($JQ '.data[].info_ratio' $temp/peeringdb_asn.json | sed '/null/d')
  [[ -z "$traffic_volume" ]] && traffic_volume="unknown"
  as_website=$($JQ '.data[].website' $temp/peeringdb_asn.json | sed '/null/d')
  pol_general=$($JQ '.data[].policy_general?' $temp/peeringdb_asn.json | sed '/null/d')
  pol_locations=$($JQ '.data[].policy_locations?' $temp/peeringdb_asn.json | sed '/null/d')
  pol_contracts=$($JQ '.data[].policy_contracts?' $temp/peeringdb_asn.json | sed '/null/d')
  [[ -n "$pol_general" ]] || pol_general="-"
  notes=$(jq -r '.data[].notes' $temp/peeringdb_asn.json | sed 's/\. /\.\n/g' | fmt -s -w 80 | tr -d '*' | sed 's/^[ \t]*//;s/[ \t]*$//')
  rir_status=$($JQ '.data[].rir_status' $temp/peeringdb_asn.json)
  looking_glass=$($JQ '.data[].looking_glass' $temp/peeringdb_asn.json | sed '/null/d')
  route_server=$($JQ '.data[].route_server' $temp/peeringdb_asn.json | sed '/null/d')
  policy_url=$($JQ '.data[].policy_url?' $temp/peeringdb_asn.json | sed '/null/d')
  ix_count=$($JQ '.data[].ix_count?' $temp/peeringdb_asn.json)
  ipv6_support=$($JQ '.data[].info_ipv6?' $temp/peeringdb_asn.json)
  unicast=$($JQ '.data[].info_unicast?' $temp/peeringdb_asn.json)
  multicast=$($JQ '.data[].info_multicast?' $temp/peeringdb_asn.json)
  via_route_servers=$($JQ '.data[].info_never_via_route_servers' $temp/peeringdb_asn.json)
  if [ -n "$ix_count" ] && [[ $ix_count -gt 0 ]]; then
    $CURL -s -m 20 "https://www.peeringdb.com/api/net/${object_id}" > $temp/ix_as.json
    ix_results=$($JQ '.data[] | .netixlan_set[] | {IXID: .ix_id, IXNAME: .name}?' $temp/ix_as.json | tr -d '{",}' |
    sed '/^$/d' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/IXID:/\[/' | sed 's/IXNAME:/\],IXNAME~/' | cut -d ':' -f -1 |
    awk -F'--' '{print $1}' | tr -d ' ' | tr '[:space:]' ' ' | sed 's/\[/\n[ /g' | sort -u | awk -F'IXNAME~' '{print $2,$1}' |
    sort -t '[' -k 1 | tr -d ' ' | tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/,$//' | fmt -w 70 | sed 's/\[/ \[/g' |
    sed 's/\],/\], /g' | sed G; echo '')
    [[ -n "$ix_results" ]] && ix_presence=$(echo -e "\n\n$ix_results") || ix_presence="NA"
  fi
fi
asname=$($JQ '.data.holder' $temp/asov.json | awk -F' ' '{print $1}')
[[ $rir = "lacnic" ]] && f_HEADLINE3 "[ASN]   $1   ($file_date)" || f_HEADLINE3 "[ASN]   $1   $asname   ($file_date)"
echo "[@]: $as_abuse" ; echo -e "____\n"
echo -e "\nName:             $($JQ '.data.holder' $temp/asov.json), $as_cc"
[[ $rir = "arin" ]] && [[ ${as_number} =~ "-" ]] && echo -e "\nAS Number:        $as_number"
if [ -n "$spamhaus_listed" ]; then
  echo -e "\nSpamhaus:         ! $spamhaus_comment listed DON'T ROOT OR PEER!"
fi
if [ $peering_db_results = "false" ]; then
  echo -e "\nStatus:           $as_status | $as_cc, $alloc_date | $(f_toUPPER "$rir")\n"
else
  if [ -n "$as_aka" ] && [[ $(f_countW "$as_aka") -le 5 ]]; then
    echo -e "\nAka:              $as_aka"
  fi
  if [ -n "$as_type" ]; then
    [[ -n "$as_scope" ]] && echo -e "\nType:             $as_type;  Scope: $as_scope" || echo -e "\nType:             $as_type"
  fi
  [[ -n "$as_aka" ]] && [[ -n "$as_type" ]] && echo ''; [[ -n "$irr_as_set" ]] && echo -e "\nIRR AS-Set:       $irr_as_set"
  echo -e "\nStatus:           $as_status | $as_cc, $alloc_date | $(f_toUPPER "$rir") | RIR Status: $rir_status\n"
  [[ -n "$route_server" ]] || [[ -n "$looking_glass" ]] && echo ''
  [[ -n "$route_server" ]] && echo "Route Server:     $route_server"
  [[ -n "$looking_glass" ]] && echo "LookingGlass:     $looking_glass"
  if [ -n "$as_website" ] || [ -n "$policy_url" ]; then
   echo ''; [[ -n "$as_website" ]] && echo "Website:          $as_website"
    [[ -n "$policy_url" ]] && echo "Policy URL:       $policy_url"
  fi
  if [ -n "$as_aka" ] && [[ $(f_countW "$as_aka") -gt 5 ]]; then
    echo ''; f_Long; echo -e "\nAka:\n\n$as_aka\n" | fmt -s -w 60
  fi
  [[ -n "$notes" ]] && f_Long && echo -e "\"$notes\"" || echo ''; f_Long
  echo -e "\nTRAFFIC\n"
  if [ -n "$traffic_volume" ] || [ -n "$traffic_ratio" ]; then
    echo -e "Volume:  $traffic_volume;  Ratio:  $traffic_ratio\n"
  else
    echo -e "No data\n"
  fi
  echo -e "\nPROTOCOLS\n"
  echo -e "Unicast: $unicast | Multicast: $multicast | IPv6: $ipv6_support | Never via Route Servers: $via_route_servers\n"
fi
f_Long
if [ $as_status = "Active" ]; then
  echo -e "\nPEERING\n"
  echo -e "Peers (RIS): $nbc_uniq  ($nbc_left left, $nbc_right right, $nbc_unc uncertain) | IX Count: $ix_count\n"
fi
if [[ $trans4_count -gt 0 ]] || [[ $trans6_count -gt 0 ]]; then
  echo -e "\nTRANSIT\n"
  echo -e "Prefixes:  $trans4_count (IPv4)  $trans6_count (IPv6)\n"
fi
if [ $peering_db_results = "true" ]; then
  echo -e "\nPOLICIES\n"
  echo -e "General: $pol_general | Locations: $pol_locations | Contracts: $pol_contracts\n"
fi
f_Long; echo -e "\nPREFIXES\n\n"
[[ $v4_low_count -gt 0 ]] && print_low4="(not announced: $v4_low_count)" || print_low4=''
[[ $v6_low_count -gt 0 ]] && print_low6="(not announced: $v6_low_count)" || print_low6=''
echo -e "IPv4  -  Whois: $v4_whois_true;  BGP: $v4_bgp_count  $print_low4\n"
echo -e "IPv6  -  Whois: $v6_whois_true;  BGP: $v6_bgp_count  $print_low6\n"
f_HEADLINE2 "CONTACT\n"; f_POC "$temp/whois" | fmt -s -w 100
if [ $as_status = "Active" ]; then
    [[ -n "$irr_as_set" ]] && f_AS_SET "$(echo "$irr_as_set" | awk -F'::' '{print $NF}')"
  if [[ $ix_count -gt 0 ]]; then
    f_HEADLINE2 "IX PRESENCE [IX-ID]: $ix_count"; [[ $ix_count -gt 2 ]] && echo ''
    if [[ $ix_count -lt 52 ]]; then
      echo -e "$ix_presence\n"
    else
      echo -e "Output written to file"
      ix_out="${outdir}/AS$s.IX.${file_date}.txt"; echo '' > $ix_out
      f_HEADLINE "AS $s IX PRESENCE [IX-ID] | $file_date" >> $ix_out; echo -e "Memberships: $ix_count\n" >> $ix_out
      echo -e "\n$ix_presence\n" | fmt -s -w 75 | sed G >> $ix_out
    fi
  fi
fi
if [[ $pfx_total -gt "0" ]]; then
  f_HEADLINE2 "BGP PREFIXES\n"
  [[ -n "$v4_bgp" ]] && echo -e "\n -- IPv4 --\n\n" && echo "$v4_bgp" | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -s -w 55 | sed G
  [[ -n "$v6_bgp" ]] && echo -e "\n -- IPv6 --\n\n" && echo "$v6_bgp" | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -s -w 55 | sed G
  if [ -n "$v4_low_vis" ] || [ -n "$v6_low_vis" ]; then
    echo ''; f_HEADLINE2 "LOW VISIBILITY / NOT ANNOUNCED\n\n"
    [[ -n "$v4_low_vis" ]] && echo "$v4_low_vis" | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -s -w 55 | sed G
    [[ -n "$v6_low_vis" ]] && echo "$v6_low_vis" | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -s -w 55 | sed G
  fi
fi
if [ -n "$nb_left" ] || [ -n "$nb_right" ]; then
  if [ $nbc_left -gt 0 ] && [ $nbc_left -le 80 ]; then
    f_HEADLINE2 "PEERS (left)\n\n"
    for nbl in $nb_left; do
      $DIG +short as${nbl}.asn.cymru.com TXT | tr -d '"' | sed 's/^[ \t]*//;s/[ \t]*$//' | cut -d '|' -f 1,2,3,5 | cut -d ',' -f -1 |
      sed 's/ripencc/ripe/'
    done
  fi
  if [ $nbc_right -gt 0 ] && [ $nbc_right -le 60 ]; then
    f_HEADLINE2 "PEERS (right)\n\n"
    for nbr in $nb_right; do
      $DIG +short as${nbr}.asn.cymru.com TXT | tr -d '"' | sed 's/^[ \t]*//;s/[ \t]*$//' | cut -d '|' -f 1,2,3,5 | cut -d ',' -f -1 |
      sed 's/ripencc/ripe/'
    done
  fi
  if [[ $nbc_left -gt 80 ]] || [[ $nbc_right -gt 60 ]]; then
    print_peers="${outdir}/AS$1.PEERS.${file_date}.txt"
    print_nb_left=$(echo "$nb_left" | sort -ug | tr '[:space:]' ' '  | sed 's/ /  /g' | sed 's/^[ \t]*//;s/[ \t]*$//' |
    fmt -w 60 | sed G)
    print_nb_right=$(echo "$nb_right" | sort -ug | tr '[:space:]' ' '  | sed 's/ /  /g' | sed 's/^[ \t]*//;s/[ \t]*$//' |
    fmt -w 60 | sed G)
    print_nb_uncertain=$(echo "$nb_uncertain" | sort -ug | tr '[:space:]' ' '  | sed 's/ /  /g' | sed 's/^[ \t]*//;s/[ \t]*$//' |
    fmt -w 60 | sed G)
    echo '' > $print_peers; f_HEADLINE "AS $1 NEIGHBOURS" >> $print_peers
    [[ -n "$print_nb_left" ]] && echo -e "\nLEFT\n\n$print_nb_left\n" >> $print_peers
    [[ -n "$print_nb_right" ]] && echo -e "\nRIGHT\n\n$print_nb_right\n" >> $print_peers
    [[ -n "$print_nb_uncertain" ]] && echo -e "\nUNCERTAIN\n\n$print_nb_uncertain\n" >> $print_peers
    if [[ $nbc_left -lt 300 ]] && [[ $nbc_right -lt 300 ]]; then
      [[ -n "$print_nb_left" ]] && f_HEADLINE2 "PEERS (LEFT)\n\n" && echo "$print_nb_left"
      [[ -n "$print_nb_right" ]] && echo ' ' && f_HEADLINE2 "PEERS (RIGHT)\n\n" && echo "$print_nb_right"
      if [ -n "$nb_uncertain" ] && [[ $nbc_unc -lt 300 ]]; then
        echo ' '; f_HEADLINE2 "PEERS (UNCERTAIN)\n\n" && echo "$print_nb_uncertain"
      fi
    fi
  fi
fi
}

f_AS_PFX(){
if [ -f $temp/as_pfx.json ]; then
  print_p4=$($JQ '.data.prefixes.v4.originating[]' $temp/as_pfx.json | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n -u |
  tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -s -w 55; echo '')
  print_p6=$($JQ '.data.prefixes.v6.originating[]' $temp/as_pfx.json | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -s -w 55; echo '')
  if [ -n "$print_p4" ] || [ -n "$print_p6" ]; then
    echo -e "\nPREFIXES\n"; [[ -n "$print_p4" ]] && echo -e "$print_p4\n"
    [[ -n "$print_p6" ]] && echo -e "$print_p6\n"
  fi
fi

}
f_AS_SET(){
$WHOIS -h whois.radb.net -- "$1" > $temp/as_set
[[ -f $temp/as_set ]] && as_set=$(grep -E "^as-set:" $temp/as_set | awk '{print $NF}' | tr -d ' ')
if [ -n "$as_set" ]; then
  if [ $target_type = "as_set" ]; then
    f_HEADLINE2 "AS-SET: $as_set\n\n"
  else
    [[ $option_detail = "1" ]] && echo -e "\nAS-Set: $as_set\n" || f_HEADLINE2 "AS-SET: $as_set\n\n"
  fi
  member_count=$(grep -c 'members:' $temp/as_set)
  if [[ $member_count -gt 0 ]]; then
    grep -E "^descr:" $temp/as_set | cut -s -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//'
    echo -e "\nMntner: $(grep -E "^mnt-by:" $temp/as_set | cut -s -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')"
    echo -e "Source: $(grep -E "^source:" $temp/as_set | cut -s -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')"
    members=$(grep 'members:' $temp/as_set | cut -s -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/$/,/' |
    sed 's/as/AS/g' | tr '[:space:]' ' ' ; echo '')
    if [[ $(grep -c 'members:' $temp/as_set) -lt 5 ]]; then
      echo -e "\nMembers: $members\n"
    else
      echo -e "\n\nMEMBERS\n"
      echo -e "$members"  | fmt -w 60 | sed 's/,$//'; echo ''
    fi
  fi
fi
}

f_AS_SHORT(){
unset as_org; unset as_orgid; unset as_name; unset as_rir; unset as_set
[[ -f $temp/asov.json ]] && rm $temp/asov.json
$CURL -s -m 15 --location --request GET "https://stat.ripe.net/data/as-overview/data.json?resource=${1}" > $temp/asov.json
[[ $domain_enum = "false" ]] && as_set=$(f_AS_SET "as-$s"); announced=$($JQ '.data.announced' $temp/asov.json)
as_sum=$($DIG +short as${1}.asn.cymru.com TXT | tr -d '"' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/ripencc/ripe/')
[[ -z "$announced" ]] && announced="no data"
if [[ $announced = "true" ]]; then
  $CURL -s -m 15 --location --request GET "https://stat.ripe.net/data/ris-prefixes/data.json?resource=${1}&list_prefixes=true&types=o" > $temp/as_pfx.json
  origin_v4=$($JQ '.data.counts.v4.originating' $temp/as_pfx.json); origin_v6=$($JQ '.data.counts.v6.originating' $temp/as_pfx.json)
fi
spamhaus_listed=$(grep -sw "$1" ${file_date}.asndrop.list)
[[ -n "$spamhaus_listed" ]] && spamhaus_comment=$(grep -w "$1" ${file_date}.asndrop.txt)
as_rir=$(echo "$as_sum" | cut -d '|' -f 3 | tr -d ' '); as_cc=$(echo "$as_sum" | cut -d '|' -f 2 | tr -d ' ')
alloc=$(echo "$as_sum" | cut -d '|' -f 3,4 | tr [:lower:] [:upper:] | cut -d '-' -f -2 | sed 's/^[ \t]*//;s/[ \t]*$//')
as_name=$($JQ '.data.holder' $temp/asov.json | cut -d ' ' -f 1)
if [ $as_rir = "lacnic" ]; then
  $WHOIS -h whois.lacnic.net as$1 > $temp/lacnic_as; as_abuse=$(f_printLACNIC_ABUSE_C "$temp/lacnic_as")
else
  as_abuse=$($CURL -s -m 10 --location --request GET "https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=${1}" |
  $JQ '.data.abuse_contacts[]' | tr '[:space:]' ' ' ; echo '')
  if [ $as_rir = "arin" ]; then
    as_org=$($WHOIS -h whois.pwhois.org "registry source-as=$1"  | grep -E -m 1 "^Org-Name:"  | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//')
  else
    as_org=$($JQ '.data.holder' $temp/asov.json | awk -F '-' '{print $NF}' | sed 's/^[ \t]*//;s/[ \t]*$//')
  fi
fi
if [ $domain_enum = "true" ]; then
  echo -e "\nAS $1"
else
  if [[ $choice = "w1" ]] || [[ $choice = "w3" ]]; then
    [[ -n "$as_set" ]] && echo -e "\n$1"  || echo -e "\nAS $1\n"
  else
    [[ -n "$as_set" ]] && f_HEADLINE2 "$1\n" && echo -e "$as_set\n" || f_HEADLINE2 "AS $1\n"
  fi
  [[ -n "$as_set" ]] && [[ -n "$alloc" ]] && echo -e "\nAut-Num: $1\n"
fi
[[ -n "$as_org" ]] && echo -e "\n$as_name - $as_org, $as_cc\n" || echo -e "\n$as_name, $as_cc\n"
if [[ $announced = "true" ]]; then
  echo -e "$alloc | Active: $announced | Prefixes: $origin_v4 (v4) $origin_v6 (v6) | $as_abuse\n" > $temp/as_short1
else
  echo -e "$alloc | Active: $announced | $as_abuse\n" > $temp/as_short1
fi
[[ -n "$spamhaus_listed" ]] && echo -e "\n  ! $spamhaus_comment  listed in Spamhaus DON'T ROOT OR PEER ! \n" >> $temp/as_short1
[[ -f $temp/as_short1 ]] && cat $temp/as_short1 | tee ${outdir}/AS${1}_BGP_PREFIXES.txt && rm $temp/as_short1
f_AS_PFX | tee -a ${outdir}/AS${1}_BGP_PREFIXES.txt > $temp/as_short2
if [ $domain_enum = "true" ]; then
 [[ $as_rir = "lacnic" ]] && echo $1 >> $temp/lacnic_asns
elif [ $target_type = "as" ]; then
  cat $temp/as_short2
fi
[[ -f $temp/as_short2 ]] && rm $temp/as_short2
}

f_getASNAME(){
local asnum="$*"
spamhaus_listed=$(grep -sw "$asnum" ${file_date}.asndrop.list)
[[ -n "$spamhaus_listed" ]] && spamhaus_comment=$(grep -w "$asnum" ${file_date}.asndrop.txt)
if [ $target_type = "prefix" ]; then
  asname=$($JQ '.data.asns[0].holder' $temp/pov.json)
else
  asname=$($CURL -s -m 7 --location --request GET "https://stat.ripe.net/data/as-overview/data.json?resource=${asnum}" | $JQ '.data.holder')
fi
as_cc=$($DIG +short as$asnum.asn.cymru.com TXT | cut -d '|' -f 2 | sed 's/^[ \t]*//;s/[ \t]*$//')
if [ $target_type = "net" ] || [ $target_type = "default" ] || [ $target_type = "hop" ]; then
  echo -e "\nASN:          $asnum,  $asname, $as_cc"
[[ -n "$spamhaus_listed" ]] && echo -e "\n              ! $spamhaus_comment listed in Spamhaus DON'T ROOT OR PEER!"
elif [ $target_type = "prefix" ]; then
  echo -e "$asnum, $asname, $as_cc\n"
  [[ -n "$spamhaus_listed" ]] && echo -e "! $spamhaus_comment listed in Spamhaus DON'T ROOT OR PEER!\n"
else
  if [ -n "$spamhaus_listed" ]; then
    echo "AS $asnum, $asname, $as_cc  ! listed in Spamhaus DON'T ROOT OR PEER!"
  else
    echo "AS $asnum, $asname, $as_cc"
  fi
fi
}

#-------------------------------  BGP / RPKI STATUS  -------------------------------

f_BGP_UPDATES(){
local p="$*"
$CURL -s --location --request GET "https://stat.ripe.net/data/bgp-update-activity/data.json?resource=${p}&num_hours=24" > $temp/update.json
announcements=$($JQ '.data.updates[] | .announcements' $temp/update.json)
if [ -n "$announcements" ]; then
  f_HEADLINE2 "BGP UPDATES - $p (past 24 hrs)\n"
  $JQ '.data.updates[] | {time: .starttime, withdrawals: .withdrawals, announcements: .announcements}' $temp/update.json | tr -d '{"}' |
  sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' | sed 's/T/  /g' | tr '[:space:]' ' ' | sed 's/time: /\n/g' | sed 's/,/  | /g' |
  sed 's/withdrawals:/withdrawals: /' | sed 's/announcements:/announcements: /'; echo ''
fi
}

f_getPFX(){
local pfx_query=$(echo $1 | cut -d '/' -f 1 | cut -d '-' -f 1)
rev=$(f_REVERSE "$pfx_query")
if [[ $pfx_query =~ $REGEX_IP4 ]]; then
    $DIG +short txt ${rev}.origin.asn.cymru.com | tr -d '"' | cut -s -d '-' -f -2 | sed 's/^[ \t]*//;s/[ \t]*$//'
else
    $DIG +short txt ${rev}.origin6.asn.cymru.com | tr -d '"' | cut -s -d '-' -f -2 | sed 's/^[ \t]*//;s/[ \t]*$//'
fi
}

f_getPFX_PEERS(){
px=$(echo $1 | cut -d '/' -f 1)
$DIG +short $(awk -F'.' '{printf $4 "." $3 "." $2 "." $1}' <<<$px).peer.asn.cymru.com TXT | tr -d '"' | cut -d '|' -f -2 | sed 's/^[ \t]*//;s/[ \t]*$//'
}

f_printLG(){
f_HEADLINE2 "Showing results for $collector\n\n"
print_lg=$(echo "$1" | tr -d '{,\"}' | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' | sed 's/PFX:/\n\n\n\*>          /g' | sed 's/ASN:/  AS/' |
sed 's/Origin:/\nOrigin:     /' | sed 's/ASPath:/\n\nAS Path:    /g' | sed 's/Community:/\nCommunity:  /' | sed 's/NextHop:/\nNext Hop:   /' | sed 's/^ *//' |
sed '/./,$!d'; echo ''); echo -e "$print_lg\n"
origin_as=$(echo "$print_lg" | grep -E -m 1 "^ASN:" | grep -sEo "[0-9]{1,11}")
f_HEADLINE2 "ASNS\n\n"
for peer in $(echo "$print_lg" | grep -E "^AS Path:" | grep -sEo "[0-9]{1,11}" | grep -v "$origin_as:" | sort -ug); do
  $DIG +short as$peer.asn.cymru.com TXT | tr -d '"' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/|/G'
done
}

f_ROUTE(){
local s="$*"; as=""; prfx=""
if [ $target_type = "net" ]; then
  netn=$(grep -sE -m 1 "^Net-Name:" $temp/pwhois | awk '{print $NF}' | tr -d ' ')
  prfx=$(grep -E "^Prefix:" $temp/pwhois | awk '{print $NF}')
  as=$(grep -E "^Origin-AS:" $temp/pwhois | awk '{print $NF}' | tr -d 'AS' | sed 's/^[ \t]*//;s/[ \t]*$//')
else
  if [ $target_type = "web" ] || [ $target_type = "hostname" ] || [ $target_type = "domain" ]; then
    f_getPFX "$s" | cut -s -d '|' -f -2 | head -1 > $temp/pfx_tmp
  fi
  prfx=$(cut -s -d '|' -f 2 $temp/pfx_tmp | tr -d ' '); as=$(cut -s -d '|' -f 1 $temp/pfx_tmp | tr -d ' ')
fi
if [ -n "$as" ]; then
  spamhaus_listed=$(grep -sw "$prfx" ${file_date}.ip_drop.txt)
  rpki_status=$($CURL -s -m 7 --location --request GET "https://stat.ripe.net/data/rpki-validation/data.json?resource=$as&prefix=$prfx" | $JQ '.data.status')
  if [ $target_type = "net" ] || [ $target_type = "default" ]; then
    if [ $target_type = "default" ]; then
      print_prefix=$(cut -s -d '|' -f 2,3,4 $temp/pfx_tmp | tail -1 | sed 's/^[ \t]*//;s/[ \t]*$//')
      echo -e "\n\nBGP:          $(f_toUPPER "$print_prefix") | ROA: $rpki_status"
    else
      if [ $rir = "arin" ] || [ $rir = "lacnic" ]; then
        echo -e "\nBGP:          $prfx,  ROA: $rpki_status"
      else
        nname_wh=$($JQ '.data.records[0]? | .[] | select (.key=="netname") | .value' $temp/whois.json)
        nname_pwh=$(grep -sE -m 1 "^Net-Name:" $temp/pwhois | awk '{print $NF}' | tr -d ' ')
        if [ $nname_wh = $nname_pwh ]; then
          echo -e "\nBGP:          $prfx,  ROA: $rpki_status"
        else
          echo -e "\nBGP:          $prfx | $netn | ROA: $rpki_status"
        fi
      fi
      [[ -n "$spamhaus_listed" ]] && echo -e " !            Prefix listed in Spamhaus DON'T ROUTE OR PEER !\n"
    fi
    f_getASNAME "$as"
  else
    echo -e "*> $prfx - ROA: $rpki_status - $(f_getASNAME "$as")\n"
    [[ -n "$spamhaus_listed" ]] && echo -e " ! Prefix listed in Spamhaus DON'T ROUTE OR PEER !\n"
  fi
else
  if [ $target_type = "net" ] || [ $target_type = "default" ]; then
    echo -e "\nBGP:          false"
  else
    echo -e "*> BGP: false"
  fi
fi
[[ $target_type = "default" ]] && echo ''
}

f_PREFIX(){
as=$($JQ '.data.asns[0].asn' $temp/pov.json); vis=$(f_VIS "$1")
as_cc=$($DIG +short as$as.asn.cymru.com TXT | cut -d '|' -f 2,3 | sed 's/|/,/' | tr -d ' ' | sed 's/,/, /')
$CURL -s -m 5 --location --request GET "https://stat.ripe.net/data/rpki-validation/data.json?resource=$as&prefix=$1" > $temp/rpki.json
pfx_rir=$($JQ '.data.block.desc' $temp/pov.json | cut -s -d '(' -f 1 | sed 's/^[ \t]*//;s/[ \t]*$//')
f_ROUTE_CONS "$1" > $temp/route_cons; pfx_peers=$(f_getPFX_PEERS "$1")
routing_consistency=$(grep -v "$1" $temp/cons_sorted)
in_whois=$(grep -w "$1" $temp/cons | awk -F'WHOIS:' '{print $2}' | awk '{print $1}' | grep -sEo "true|false")
less_specifics=$($JQ '.data.less_specifics[] | {PFX: .prefix, OR: .origin}?' $temp/bgp.json | tr -d '{},"' | sed 's/^[ \t]*//;s/[ \t]*$//' |
sed '/^$/d' | sed '/OR:/a)' | tr '[:space:]' ' ' | sed 's/PFX: /\n/g' | sed 's/OR:/(AS/' | tr -d ' ' | sed 's/(AS/ (AS /'; echo '')
more_specifics=$($JQ '.data.more_specifics[] | {PFX: .prefix, OR: .origin}?' $temp/bgp.json | tr -d '{},"' | sed 's/^[ \t]*//;s/[ \t]*$//' |
sed '/^$/d' | sed '/OR:/a)' | tr '[:space:]' ' ' | sed 's/PFX: /\n/g' | sed 's/OR:/(AS/' | tr -d ' ' | sed 's/(AS/ (AS /'; echo '')
echo -e "\nPREFIX\n\n$1 | $pfx_rir | BGP: $($JQ '.data.announced' $temp/pov.json) | Whois: $in_whois\n"
echo -e "\nASN\n\n$as, $($JQ '.data.asns[0].holder' $temp/pov.json)  ($as_cc)\n"
echo -e "\nRIS\n\n$vis\n"; echo ''; f_RPKI; echo ''
[[ -n "$less_specifics" ]] && echo -e "\nLESS SPECIFIC\n\n$less_specifics\n"
[[ -n "$more_specifics" ]] && echo -e "\nMORE SPECIFIC\n\n$more_specifics\n"
if [ -n "$pfx_peers" ]; then
  echo -e "\nPEERS\n"
  for p in $pfx_peers; do
    $DIG +short as${p}.asn.cymru.com TXT | tr -d '"' | sed 's/^[ \t]*//;s/[ \t]*$//' | cut -s -d '|' -f 1,2,5 | cut -d ' ' -f -5
  done
fi
if [ -n "$routing_consistency" ]; then
  echo -e "$routing_consistency" | sed '/^$/d' | sed 's/| /\n\n/' | sed '/|/G' | sed 's/false/false !/g' > $temp/routing_consistency
fi
}

f_ROUTE_CONS(){
$CURL -s -m 7 --location --request GET "https://stat.ripe.net/data/prefix-routing-consistency/data.json?resource=${1}" > $temp/cons.json
if [ -f $temp/cons.json ]; then
  $JQ '.data.routes[] | {PFX: .prefix, RIS: .in_bgp, WHOIS: .in_whois, ASNUM: .origin, ASNAME: .asn_name}' $temp/cons.json |
  tr -d '{",}' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d'| tr '[:space:]' ' ' | sed 's/PFX: /\n/g' |
  sed 's/RIS:/| RIS:/' | sed 's/WHOIS:/| WHOIS:/' | sed 's/ASNUM:/| AS/' | sed 's/ ASNAME:/,/' | grep '|' > $temp/cons
  all_true=$(grep -sEw "RIS: true \| WHOIS: true" $temp/cons)
  ris_false=$(grep -sEw "RIS: false \| WHOIS: true" $temp/cons)
  whois_false=$(grep -sEw "RIS: false \| WHOIS: false" $temp/cons)
  [[ -n "$all_true" ]] && echo "$all_true" > $temp/cons_sorted
  if [ -n "$ris_false" ]; then
    [[ -n "$all_true" ]] && echo '' >> $temp/cons_sorted; echo "$ris_false" >> $temp/cons_sorted
  fi
  if [ -n "$whois_false" ]; then
    [[ -n "$all_true" ]] || [[ -n "$ris_false" ]] && echo '' >> $temp/cons_sorted; echo "$whois_false" >> $temp/cons_sorted
  fi
  if [[ $(grep -c '|' $temp/cons_sorted) -gt 1 ]] || [ -n "$ris_false" ] || [ -n "$whois_false" ]; then
    f_HEADLINE2 "BGP/RIS - WHOIS CONSISTENCY\n\n"
    if [[ $(grep -c '|' $temp/cons_sorted) -gt 1 ]]; then
      cut -d '-' -f 1 $temp/cons_sorted; echo ''; cut -s -d '|' -f 4 $temp/cons_sorted | sed 's/^[ \t]*//;s/[ \t]*$//' | sort -u
    else
      grep '|' $temp/cons_sorted  | sed 's/| /\n\n/' | sed '/|/G'; echo ''
    fi
  fi
fi
}

f_RPKI(){
rpki_status=$($JQ '.data.status' $temp/rpki.json); echo -e "\nROAs\n"
if [ $rpki_status = "unknown" ]; then
  echo -e "$rpki_status\n"
else
  roa_pfx=$($JQ '.data.validating_roas[0].prefix' $temp/rpki.json)
  roa_or=$($JQ '.data.validating_roas[0].origin' $temp/rpki.json); max_len=$($JQ '.data.validating_roas[0].max_length' $temp/rpki.json)
  valid=$($JQ '.data.validating_roas[0].validity' $temp/rpki.json); echo -e "$valid >  $roa_pfx >  $roa_or  > max. /$max_len\n"
fi
}

f_VIS(){
local p="$*"; pfx_ip=$(echo $p | cut -d '/' -f 1)
$CURL -s "https://stat.ripe.net/data/routing-status/data.json?resource=${p}" > $temp/bgp.json
if [[ ${pfx_ip} =~ $REGEX_IP4 ]] ; then
  visibility=$($JQ '.data.visibility.v4.ris_peers_seeing' $temp/bgp.json)
  peers_total=$($JQ '.data.visibility.v4.total_ris_peers' $temp/bgp.json)
else
  visibility=$($JQ '.data.visibility.v6.ris_peers_seeing' $temp/bgp.json)
  peers_total=$($JQ '.data.visibility.v6.total_ris_peers' $temp/bgp.json)
fi
f_seen=$($JQ '.data.first_seen.time' $temp/bgp.json | cut -d 'T' -f 1)
f_seen_origin=$($JQ '.data.first_seen.origin' $temp/bgp.json)
echo "Visibility: $visibility/$peers_total   First seen: $f_seen  ($f_seen_origin)"
}

#-------------------------------  PING, MTU, TRACEROUTE  -------------------------------

f_GEO_PING(){
f_HEADLINE "SHODAN GEO PING |  $1  | $(date -R))"
$CURL -sL -m 20 "https://geonet.shodan.io/api/geoping/$1" |
$JQ '.[] | {Alive: .is_alive, RTT_avg: .avg_rtt, Send: .packets_sent, Rcvd: .packets_received, From: .from_loc.city, CC: .from_loc.country}' |
tr -d '[{,"}]' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' | sed 's/^/| /' | tr '[:space:]' ' ' | sed 's/| Alive:/\n\n\nAlive:/g' |
sed 's/RTTavg:/RTT \(avg\):/' | sed 's/| From:/  <- /' | sed 's/ | CC:/\,/' | sed 's/_/ /'; echo ''
}

f_MTR(){
echo ''; f_Long; echo -e "$1 MTR\n"
${run_as_sudo} $MTR "${trace_array[@]}" --mpls -w -o "  L  D  A  W  M  X" $1 | sed '/Start:/G' | sed '/Javg/G' > $temp/mtr.txt; cat $temp/mtr.txt
echo -e "\n___________________________________________\n\nAVG = average RTT in ms;  Wrst = worst RTT; \nJavg = average jitter;  Jmax = max jitter\n"
}

f_PATH_MTU(){
if [ -n "$is_admin" ] && ! [[ $1 =~ $REGEX_IP6 ]]; then
  echo ''; $run_as_sudo $NMAP $custom_inf -R --resolve-all -sS -p 53,80 --script=path-mtu.nse $1 2> /dev/null |
  grep -E "scan report|PMTU" | sed '/Nmap scan/{x;p;x;G}' | sed 's/Nmap scan report for/* /' | sed 's/|_path-mtu:/  /'
fi
}

f_getMTU(){
if [ -f $temp/tpath ]; then
  pmtu=$(grep 'Resume' $temp/tpath | awk -F'pmtu' '{print $2}' | awk '{print $1}')
  hops=$(grep 'Resume' $temp/tpath | awk -F'hops' '{print $2}' | awk '{print $1}')
  echo -e "\n$1  ->  MTU: $pmtu;  Hops: $hops\n"
  rm $temp/tpath
fi
}

f_PATH_MTU_ALT(){
echo -e "\n$1\n"
if type tracepath &> /dev/null; then
  f_HEADLINE2 "$1  PATH MTU  ($file_date)\n"
  if [ $target_cat = "hostname" ]; then
    has_ip4=$(f_RESOLVE_v4 "$1")
    has_ipv6=$(f_RESOLVE_v6 "$1")
    if [ -n "$has_ip4" ]; then
      for a in $has_ip4; do $TPATH -n -4 $a | sed 's/^ *//' > $temp/tpath; f_getMTU "$a"; done
    fi
    if [ -n "$has_ip6" ]; then
      for z in $has_ip6; do $TPATH -n -6 $z | sed 's/^ *//' > $temp/tpath; f_getMTU "$z"; done
    fi
  elif [ $target_cat = "host4" ]; then
    $TPATH -n -4 -m 25 $1 | sed 's/^ *//' > $temp/tpath; f_getMTU "$1"
  elif [ $target_cat = "host6" ]; then
    $TPATH -n -6 -m 25 $1 | sed 's/^ *//' > $temp/tpath; f_getMTU "$1"
  fi
fi
}

f_PING(){
[[ $1 =~ $REGEX_IP6 ]] && timeout 7 $PING -6 -c 5 $1 > $temp/ipg || timeout 7 ping -c 5 $1 > $temp/ipg
icmp_packets=$(grep packets $temp/ipg | cut -d ',' -f -2 | sed 's/packets transmitted/sent/' | sed 's/received/ok/' |
sed 's/^[ \t]*//;s/[ \t]*$//')
if [ -n "$icmp_packets" ]; then
  icmp_avg=$(sed -n '/---/,$p' $temp/ipg | grep 'rtt' | cut -d '=' -f 2 | awk -F'/' '{print $2}' | tr -d ' ')
  icmp_max=$(sed -n '/---/,$p' $temp/ipg | grep 'rtt' | cut -d '=' -f 2 | awk -F'/' '{print $3}' | tr -d ' ')
  icmp_mdev=$(sed -n '/---/,$p' $temp/ipg | grep 'rtt' | cut -d '=' -f 2 | awk -F'/' '{print $4}' | tr -d 'ms' | tr -d ' ')
  actual_ttl=$(grep -so "ttl=.[0-9]${2,3}" $temp/ipg | cut -s -d '=' -f 2 | tail -1 | tr -d ' ')
  num_hops=$(($default_ttl - $actual_ttl))
  [[ $target_type = "web" ]] || echo ''
  echo -e "ICMP:  $icmp_packets | Avg: $icmp_avg ms | Max: $icmp_max ms | Mdev: $icmp_mdev ms | Hops: $num_hops"
else
  echo -e "ICMP:  failed"
fi; echo ''; f_printNPING
}

f_printNPING(){
if [ -f $temp/np ]; then
  np_conn=$(grep 'Failed' $temp/np | awk -F'attempts:' '{print $2}' | awk '{print $1}' | tr -d ' ')
  np_ok=$(grep Failed: $temp/np | awk -F'connections:' '{print $2}' | awk '{print $1}' | tr -d ' ')
  np_avg=$(grep 'Avg rtt:' $temp/np | awk -F'Avg rtt:' '{print $2}' | awk '{print $1}' | tr -d ' ')
  np_max=$(grep 'Max rtt:' $temp/np | awk -F'Max rtt:' '{print $2}' | awk '{print $1}' | tr -d ' ')
  np_target=$(grep -m 1 'SENT' $temp/np | awk -F'>' '{print $2}' | tr -d ' ')
  print_response=$(echo "$np_conn conn, $np_ok ok | Avg: $np_avg | Max: $np_max  ($np_target)" | sed 's/ms/ ms/g')
  echo "TCP:   $print_response"; rm $temp/np
fi
}

f_TRACEPATH(){
echo ''; f_Long; echo -e "$1 TRACEPATH  ($file_date)\n\n"
$TPATH  ${trace_array[@]} $1 | sed 's/^ *//' > $temp/trace
sed '/Resume/i \\n___________________________________\n' $temp/trace; echo ''
}

f_WEB_PING(){
f_HEADLINE2 "WEB HOSTS PING\n"
for a in $(f_EXTRACT_IP4 "$1"); do
  echo -e "\n\n$a\n"; [[ -n "$NPING" ]] && $NPING --safe-payloads --tcp-connect -p 80 -c 5 $a > $temp/np; f_PING "$a"
done
for z in $(f_EXTRACT_IP6 "$1"); do
  echo -e "\n\n$z\n"; [[ -n "$NPING" ]] && $NPING -6 --safe-payloads --tcp-connect -p 80 -c 5 $z > $temp/np; f_PING "$z"
done
}

#-------------------------------  BANNERS, NMAP  -------------------------------


f_BANNERS(){
$CURL -s -m 30 https://api.hackertarget.com/bannerlookup/?q=${1}${api_key_ht} > $temp/banners.json
if [ -f $temp/banners.json ]; then
f_HEADLINE2 "$1 BANNERS (SOURCE: HACKERTARGET:COM)\n"
$JQ '{IP: .ip, FTP: .ftp, SSH: .ssh, Telnet: .telnet,  RDP: .rdp, http_Server: .http.server, http_Title: .http.title, https_Server: .https.server, https_Title: .https.title, https_CN: .https.cn, https_Org: .https.o, https_Redir: .https.redirect_location, https0_Apps: .https.apps[0], https_Apps: .https.apps[1], https443_Server: .https443.server, https443_Title: .https443.title, https443_CN: .https443.cn, https443_Org: .https443.o, https443_Redir: .https443.redirect_location, http9090_Server: .http8080.server, http9090_Title: .http8080.title, https8553_Server: .https8443.server, https8553_Title: .https8443.title, https8553_CN: .https8443.cn, https8553_Redir: .https8443.redirect_location}?' $temp/banners.json | tr -d '{,"}' |
sed 's/http_Server: null/http_Server: none\/unknown/g' | sed '/null/d' |
sed '/^$/d' | sed 's/^ *//' | sed '/^IP:/i nnnn' | tr '[:space:]' ' ' | sed 's/http_Title:/| Title:/g' |
sed 's/https_Title:/\nHTTPS Title:/g' | sed 's/https_CN:/\nHTTPS CN:/g' | sed 's/https_Org:/| Org:/g' |
sed 's/https_Redir:/\nRedirect:/g' | sed 's/https0_Apps:/\nApp:/g' | sed 's/https_Apps:/\nApp:/g' |
sed 's/https443_Title:/\n443\/HTTPS Title:/g' | sed 's/https443_CN:/\n443\/HTTPS CN:/g' | sed 's/https443_Org:/| Org:/g' |
sed 's/https443_Redir:/\nRedirect:/g' | sed 's/https4430_Apps:/\nApp:/g' | sed 's/https443_Apps:/\nApp:/g' |
sed 's/http9090_Title:/\nHTTP\/8080 Title:/g' | sed 's/https8553_Title:/\nHTTPS\/8443Title:/g' |
sed 's/https85533_CN:/HTTPS\/8443 CN:/g' | sed 's/https8553_Redir:/\nRedirect:/g' | sed 's/IP:/\n>IP:/g' | sed 's/FTP:/\nFTP:/g' |
sed 's/SSH:/\nSSH:/g' | sed 's/Telnet:/\nTelnet:/g' | sed 's/RDP:/\nRDP:/g' | sed 's/http9090_Server:/\n8080\/HTTP Server:/g' |
sed 's/https443_Server:/\n443\/HTTPS Server:/g' | sed 's/https_Server:/\nHTTPS Server:/g' |
sed 's/https85533_Server:/\n8443\/HTTPS\ Server:/g' | sed 's/http_Server:/\nHTTP Server:/g' | sed 's/server: //g' |
sed 's/nnnn/\n/g' | sed 's/^ *//' > $temp/banners
sed '/>IP:/G' $temp/banners | sed 's/>IP:/\n>/g' | sed '/./,$!d' | sed 's/^/  /' | sed 's/  >/>/'
fi
}

f_NMAP_BCAST(){
bcast=$(${run_as_sudo} $NMAP ${custom_inf} --script=$1 2>/dev/null | grep '|')
if [ -n "$bcast" ]; then
  echo "$bcast" | grep -v 'newtargets' |
  sed '/broadcast-/i \\n_______________________________________________________________________________\n\n' | sed '/broadcast-/G' |
  sed 's/|_//' | sed 's/|//' > $temp/bcast_tmp
  if grep -q 'broadcast\-dhcp\-discover:' $temp/bcast_tmp; then
    sed 's/^[ \t]*//;s/[ \t]*$//' $temp/bcast_tmp | sed '/Response/{x;p;x;G}' | sed '/Identifier:/{x;p;x;}'
  else
    cat $temp/bcast_tmp
  fi
else
  f_HEADLINE2 "$1: No response"
fi
}

f_NMAP_FWALK(){
local scan_target="$*"
target_stripped=$(echo "$scan_target" | cut -d '/' -f 1 | cut -d '-' -f 1 | tr -d ' ')
[[ $target_stripped =~ $REGEX_IP6 ]] && opt_v6="-6" || opt_v6=""
f_HEADLINE3 "[FIREWALK]   $scan_target   ($file_date)"; f_Long
$run_as_sudo $NMAP $custom_inf --script=firewalk --traceroute $opt_v6 $fw_args $1 |
grep -E "^Nmap scan|^Host seems|^Other addresses|^Not shown|^PORT|/tcp|/udp|^[0-9]{1,5}|^\|_|^\||TRACEROUTE|HOP" |
tr -d '|_' | sed 's/^|_//' | sed 's/^|//' | sed 's/^[ \t]*//;s/[ \t]*$//' |
sed 's/Nmap scan report for/\n\n\n\* /' | sed '/PORT/{x;p;x;G}' | sed '/Host is/G' | sed '/Host seems/G' | sed '/Nmap done/{x;p;x;G}' |
sed 's/Other addresses for //' | sed '/Not shown:/{x;p;x;G}' | sed 's/Not shown: //' | sed '/Service Info:/{x;p;x;}' |
sed 's/firewalk:/\n\nFIREWALK/' | sed 's/TRACEROUTE/\n\nTRACEROUTE/' | sed '/ADDRESS/{x;p;x;G}' | sed 's/^/    /' | sed 's/   \*/\*/' |
sed '/./,$!d' > $temp/fwalk
if [ -f $temp/fwalk ]; then
  cat $temp/fwalk
  sed -n '/TRACEROUTE/,$p' $temp/fwalk | grep -sEo "$IP4_ALT" | sed '1,1d' > $temp/fwalk_hops
  f_Long; f_WHOIS_TABLE "$temp/fwalk_hops"; rm $temp/fwalk
fi
}

f_printNMAP1(){
if [ -f $temp/nmap ]; then
  grep -sE "^Nmap scan report|rDNS|Not shown:|Host is|Host seems|PORT|/tcp|/udp|^MAC Address:|CVE.*|^Device type:|^Running|^OS CPE:|^Service Info:|OS guesses:|%|^Network Distance:|^OS details:|^[0-9]{1,2}|reported as filtered|TRACEROUTE|RTT|^Nmap done:|\|" $temp/nmap |
  grep -E -v "MD5:|Subject Alternative|Public Key type:|Public Key bits:|Signature Algorithm:|Not valid before:|detection performed" |
  sed '/Nmap scan report/i \_______________________________________________________________________________\n' | sed '/scan report/G' |
  sed 's/Nmap scan report for /\n/' | sed '/Not shown:/{x;p;x;}' | sed 's/Host is up/UP/' | sed 's/Not shown: //' | sed '/PORT/{x;p;x;G}' |
  sed '/MAC Address:/{x;p;x;}' | sed 's/MAC Address:/MAC: /' | sed '/Service Info:/{x;p;x;G}' | sed 's/https:\/\/vulners.com/\nhttps:\/\/vulners.com/' |
  sed '/Device type:/{x;p;x;}' | sed '/|_/G' | sed '/OS guesses:/{x;p;x;}' | sed 's/commonName=/ CN = /' |
  sed 's/organizationName=/ O = /' | sed 's/stateOrProvinceName=/ ST = /' | sed 's/countryName=/ C = /' |
  sed '/Some closed ports/G' | sed '/Nmap done/i \\n_______________________________________________________________________________\n' | fmt -s -w 120
fi
}

f_printNMAP2(){
if [ -f $temp/nmap ]; then
  grep -sE "^Nmap scan report|/tcp|/udp|^MAC Address:|^Device type:|^Running|OS guesses:|%|^OS details:|^OS CPE:|^Service Info:|^Network Distance:|^Nmap done:|\|" $temp/nmap |
  grep -E -v "MD5:|Subject Alternative|Public Key type:|Public Key bits:|Signature Algorithm:|Not valid before:|detection performed|No mobile version detected" |
  sed 's/^|_//' | sed 's/^|//' | sed 's/address-info:/\naddress-info:/' | sed 's/fingerprint-strings:/\nfingerprint-strings:\n/' |
  sed 's/ftp-anon:/\n! ftp-anon:\n/' | sed 's/http-affiliate-id:/\nhttp-affiliate-id:/' | sed 's/http-auth:/\nhttp-auth:\n/' |
  sed 's/http-auth-finder:/\nhttp-auth-finder:\n/' | sed 's/http-aspnet-debug:/\naspnet-debug:/' |
  sed 's/http-cookie-flags:/\n\nhttp-cookie-flags:/' | sed 's/http-cors:/\nhttp-cors:\n/' | sed 's/http-date:/\nhttp-date:/' |
  sed 's/http-cross-domain-policy:/\nhttp-cross-domain-policy:\n/' | sed 's/http-csrf:/\n! http-csrf:\n/' |
  sed 's/http-dombased-xss:/\n! http-dombased-xss:\n/' | sed 's/http-enum:/\nhttp-enum:/' |
  sed 's/http-jsonp-detection:/\nhttp-jsonp-detection:\n/' | sed 's/http-malware-host:/\nhttp-malware-host:/' |
  sed 's/http-methods:/\nhttp-methods:/' | sed 's/http-mobileversion-checker:/\nhttp-mobileversion-checker:/' |
  sed 's/http-open-redirect:/\nhttp-open-redirect:/' | sed 's/http-php-version:/\nhttp-php-version:/' |
  sed 's/http-phpmyadmin-dir-traversal:/\nphpmyadmin-dir-traversal:/' | sed 's/http-referer-checker:/\nhttp-referer-checker:/' |
  sed 's/http-server-header:/\nhttp-server-header:/' | sed 's/http-slowloris-check:/\n! http-slowloris-check:\n/' |
  sed 's/http-stored-xss:/\n! http-stored-xss:\n/' | sed 's/http-title:/\ntitle:/' | sed 's/http-trace:/\nhttp-trace/' |
  sed 's/http-traceroute:/\nhttp-traceroute:/' | sed 's/http-unsafe-output-escaping:/\n! http-unsafe-output-escaping:\n/' |
  sed 's/http-webdav-scan:/\nhttp-webdav-scan:\n/' | sed 's/irc-botnet-channels:/\n! irc-botnet-channels:\n/' |
  sed 's/memcached-info:/\nmemcached-info:\n/' | sed 's/mysql-empty-password:/\n! mysql-empty-password:\n/' | sed 's/nbstat:/\nnbstat:\n\n/' |
  sed 's/nfs-ls:/\nnfs-ls:\n/' | sed 's/proxy-open-http:/\n! proxy-open-http:\n/' | sed 's/http-qnap-nas-info:/\nhttp-qnap-nas-info:\n/' |
  sed 's/ssl-date:/\nssl-date:/' | sed 's/smb-double-pulsar-backdoor:/\n! smb-double-pulsar-backdoor:\n/' |
  sed 's/sip-methods:/\nsip-methods:\n/' | sed 's/smb-ls:/\nsmb-ls:\n/' | sed 's/smb-vuln-ms17-010:/\n! smb-vuln-ms17-010:\n/' |
  sed 's/ssl-known-key:/\n! ssl-known-key:/' | sed 's/rmi-vuln-classloader:/\n! rmi-vuln-classloader:\n/' |
  sed 's/smtp-strangeport:/\n! smtp-strangeport:\n/' | sed 's/ssh-hostkey:/\nssh-hostkey:\n/' |
  sed 's/ssh2-enum-algos://' | sed 's/ssl-cert:/\nssl-cert:\n/' | sed 's/vulners:/\n! vulners:\n/' |
  sed 's/xmlrpc-methods:/\nxmlrpc-methods:\n/' | sed 's/\, NetBIOS MAC:/\nNetBIOS MAC:/' |
  sed 's/Supported Methods:/Supported Methods: /' | sed 's/Potentially risky methods:/Potentially RISKY: /' |
  sed 's/Issuer:/Issuer: /' | sed 's/Not valid after: /Expires:/' | sed 's/SHA-1:/SHA-1:  /' | sed 's/commonName=/CN = /' |
  sed 's/organizationName=/O = /' | sed 's/stateOrProvinceName=/ST = /' | sed 's/countryName=/C = /' |
  sed '/kex_algorithms:/{x;p;x;}' | sed '/server_host_key_algorithms:/{x;p;x;}' | sed '/encryption_algorithms:/{x;p;x;}' |
  sed '/mac_algorithms:/{x;p;x;}' | sed '/compression_algorithms:/{x;p;x;}' |
  sed '/MAC Address:/i \\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n' |
  sed '/Service Info:/i \\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n' |
  sed '/Network Distance:/i \\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n' |
  sed '/Device type:/i \\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n' |
  sed '/OS CPE:/i \\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n' |
  sed '/OS details:/i \\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n' |
  sed 's/MAC Address:/\nMAC: /' | sed 's/OS details:/OS details: /' |
  sed 's/Running:/Running: /' | sed 's/Network Distance:/Distance: /' | sed 's/Device type:/Device type: /' |
  sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/https:\/\/vulners.com/\nhttps:\/\/vulners.com/' |
  sed '/Nmap scan report/i \\n\n_______________________________________________________________________________\n' |
  sed '/\/tcp/i \\n-------------------------------------------------------------------------------\n' |
  sed 's/cpe:\/o:/\ncpe:\/o:/' | sed 's/Aggressive OS guesses:/\nAggressive OS guesses:\n/'
   > $temp/nmap_tmp
  if [ $target_type = "web" ] || [ $target_type = "other" ]; then
    sed 's/Nmap scan report for/\n* NMAP: /g' $temp/nmap_tmp | sed '/Nmap done/d' | fmt -s -w 120 | tee $temp/nmap_output
  else
    sed 's/Nmap scan report for/\n*/g' $temp/nmap_tmp | sed '/Nmap done/d' | fmt -s -w 120 | tee $temp/nmap_output
  fi
  echo -e "\n"
fi
}

f_printNMAP_SSL(){
if [ -f $temp/nmap_ssl ]; then
  grep -E -A 1 "^Nmap scan report|^ssl-enum-ciphers:|^ssl-heartbleed:|ssl-dh-params:|^sslv2:|^ciphers:|^tls-nextprotoneg:|VULNERABLE:|TLSv1(\.[0-3])|^TLS_|^SSL2_|Anonymous|cipher|deprecated by|lower strength|message integrity|least strength:|compressors:|warnings:|^SSLv2 supported|^Check results:|Cipher Suite:|Modulus Source:|Generator Length:|ssl-date:|spdy|http" $temp/nmap_ssl |
  sed '/Nmap scan report/i \_______________________________________________________________________________\n' |
  sed '/Host is up/d' | sed 's/(/ (/' |
  sed '/NMAP scan report/a Scripts:   ssl-date, ssl-dh-params.nse, ssl-enum-ciphers.nse, ssl-heartbleed.nse, sslv2.nse, tls-nextprotoneg' |
  sed 's/Nmap scan report for/NMAP SSL:  /' | sed 's/^ssl-enum-ciphers:/\nOFFERED CIPHERS:/' | sed 's/TLSv/\nTLSv/' |
  sed 's/sslv2:/\n\nSSLv2:\n/' | sed 's/ssl-date:/\n\nSSL-DATE: /' | sed 's/tls-nextprotoneg:/\n\nTLS NEXTPROTONEG:\n/' |
  sed 's/ssl-dh-params:/\n\nDH PARAMS:\n/' | sed 's/ssl-heartbleed:/\n\nHEARTBLEED:\n/' |
  sed '/^State:/{x;p;x;}' | sed '/Check results:/{x;p;x;}' | sed 's/^ciphers://' | sed '/compressors:/{x;p;x;}' |
  sed '/least strength:/i \\n__________________\n' | sed '/least strength:/a \__________________\n' | sed 's/^ *//' | sed 's/^--//'
fi
}

f_RUN_NMAP(){
local scan_target="$*"
target_stripped=$(echo "$scan_target" | cut -d '/' -f 1 | cut -d '-' -f 1 | tr -d ' ')
if [[ $target_stripped =~ $REGEX_IP46 ]]; then
  [[ $target_stripped =~ $REGEX_IP4 ]] && option_ipv="v4" && opt_v6='' || opt_v6="-6"
else
  [[ $target_type != "web" ]] && option_ipv="v4" && opt_v6=''
fi
$run_as_sudo $proxych $NMAP "$custom_inf" "$opt_v6" "${nmap_array[@]}" "$ports" "$scan_target" "$scripts" "$script_args" 2>/dev/null > $temp/nmap
if [ $target_type = "web" ] || [ $target_type = "other" ]; then
  f_printNMAP2
else
  f_printNMAP1
fi
}

#-------------------------------  LOCAL SYSTEM  -------------------------------

f_getDEFAULT_NS(){
if type resolvectl &> /dev/null; then
  default_ns=$(/usr/bin/resolvectl status | grep -m 1 'Current DNS Server:' | cut -d ':' -f 2- | awk '{print $1}' | grep -sEo "$REGEX_IP46")
  [[ -n "$default_ns" ]] && echo "$default_ns"
fi
}

f_getDEFAULT_ROUTES(){
v4_default=$(ip -4 route show default | grep 'via' | cut -d ' ' -f 3- | sed 's/^[ \t]*//;s/[ \t]*$//')
v6_default=$(ip -6 route show default | grep 'via' | cut -d ' ' -f 3- | sed 's/^[ \t]*//;s/[ \t]*$//')
[[ -n "$v4_default" ]] && echo -e "Default: $v4_default" || echo -e "Default: No IPv4 default route"
[[ -n "$v6_default" ]] && echo -e "Default: $v6_default" || echo -e "Default: No IPv6 default route"
}

f_IP_LINK(){
interfaces=$($IP -o link show | grep -Ev "^lo|LOOPBACK" | awk '{print $2}' | tr -d ':' | sort -u)
$IP -br link show | grep -Ev "^lo|LOOPBACK" | grep 'UP' | cut -d '<' -f 1 > $temp/iflist
$IP -o link show | grep -Ev "^lo|LOOPBACK" | grep 'state UP' | awk '{print $2,$4,$5}' > $temp/ifmtu
for i in $interfaces; do
  ifmtu=$(grep 'mtu' $temp/ifmtu | grep -m 1 "$i" | awk -F 'mtu' '{print "MTU:",$2}' | sed 's/^[ \t]*//;s/[ \t]*$//')
  if_status=$(grep -m 1 "$i" $temp/iflist); echo "$if_status   $ifmtu  $ifmac"
done; echo ''
}

f_PUBIP(){
$CURL -s -m 7 "http://ip-api.com/json/?fields=10242" > $temp/pub1.json
pub1=$($JQ '.query' $temp/pub1.json)
if [ -n "$pub1" ]; then
print_pub="$pub1  ($($JQ '.countryCode' $temp/pub1.json))  $($JQ '.as' $temp/pub1.json | sed 's/AS/AS /')"
if [[ $pub1 =~ $REGEX_IP4 ]]; then
pub4="$print_pub"
pub2=$($CURL -s -m 7 -s --location --request GET "https://stat.ripe.net/data/whats-my-ip/data.json" | $JQ '.data.ip')
[[ $pub2 =~ $REGEX_IP6 ]] && pub6="$pub2"; else
pub6="$print_pub"; fi; fi
[[ -n "$pub4" ]] && echo -e "\nPublic IPv4:  $pub4"
[[ -n "$pub6" ]] && echo -e "\nPublic IPv6:  $pub6"
}

f_printIF_ADDRESSES(){
f_HEADLINE2 "INTERFACES\n"
[[ $target_type = "nic" ]] && f_IP_LINK
$IP -4 -br addr show up scope global > $temp/if4; ip -6 -br addr show up scope global > $temp/if6
nics=$($IP -br addr show up scope global | grep UP | awk '{print $1}' | tr -d ' ')
for n in $nics; do grep "$n" $temp/if4; grep "$n" $temp/if6; done
}

f_printROUTES(){
echo -e "\nROUTES:\n"
$IP route | grep -Ev "169\.254\.0\.0/16|default" | awk '{print $1}' | tr '[:space:]' ' ' | sed 's/ /  /g' ; echo ''
}

f_SYSINFO(){
echo ''; f_Long
if [[ $(/usr/bin/uname -o) =~ "Android" ]]; then
  echo -e "\nHostname: $(/usr/bin/uname -n)\n"
else
  echo -e "\nHostname: $(/usr/bin/uname -n) $(/usr/bin/hostname -I | cut -d ' ' -f -2 | sed 's/ /  /')"
  echo -e "Nserver:  $(f_getDEFAULT_NS)\n"
  f_getDEFAULT_ROUTES | sed 's/Default:/Default: /'; f_Long
fi
echo -e "\nINTERFACES\n"
$IP -s addr show up | sed '/state/{x;p;x;}' | sed -e '/./{H;$!d;}' -e 'x;/lo:/d' | sed -e '/./{H;$!d;}' -e 'x;/UNKNOWN/d' |
sed -e '/./{H;$!d;}' -e 'x;/dummy/d' | sed -e '/./{H;$!d;}' -e 'x;/DOWN/d' | grep -E -A 1 "MULTICAST|inet|inet6|RX|TX" |
sed '/--/d' | sed '/valid_lft/d' | sed '/ether/{x;p;x;G}' | sed '/group/{x;p;x;}' | sed '/RX/{x;p;x;}' | sed '/TX/{x;p;x;}' |
awk -F'brd' '{print $1}' | sed 's/link\/ether/mac  /' | sed 's/scope/ scope/'
f_HEADLINE2 "ROUTES\n\n"
if [[ $(/usr/bin/uname -o) =~ "Android" ]]; then
  $IP -4 route | sed 's/dev/ dev/'; echo ''; $IP -6 route | sed 's/dev/ dev/'
else
  $NMAP -iflist | sed -n '/METRIC/,$p' | grep -v lo | sed '/METRIC/G'
fi
}

#-------------------------------  CLEAN UP  -------------------------------

f_CLEANUP_FILES(){
[[ -f $temp/ac ]] && rm $temp/ac; [[ -f $temp/arin_nets ]] && rm $temp/arin_nets
[[ -f $temp/arin_org ]] && rm $temp/arin_org; [[ -f $temp/asov.json ]] && rm $temp/asov.json
[[ -f $temp/banners ]] && rm $temp/banners; [[ -f $temp/bgp.json ]] && rm $temp/bgp.json
[[ -f $temp/cust ]] && rm $temp/cust; [[ -f $temp/detected_ports ]] && rm $temp/detected_ports
[[ -f $temp/fwalk ]] && rm $temp/fwalk; [[ -f $temp/h3 ]] && rm $temp/h3
[[ -f $temp/h_issues ]] && rm $temp/h_issues; [[ -f $temp/dis_issues ]] && rm $temp/dis_issues
[[ -f $temp/headers ]] && rm $temp/headers; [[ -f $temp/hoplist ]] && rm $temp/hoplist
[[ -f $temp/host_ipv4 ]] && rm $temp/host_ipv4; [[ -f $temp/host_ipv6 ]] && rm $temp/host_ipv6
[[ -f $temp/inums ]] && rm $temp/inums; [[ -f $temp/mail2 ]] && rm $temp/mail2
[[ -f $temp/mail ]] && rm $temp/mail; [[ -f $temp/mx_hosts ]] && rm $temp/mx_hosts
[[ -f $temp/mx_ipv4.list ]] && rm $temp/mx_ipv4.list; [[ -f $temp/mx_ipv6.list ]] && rm $temp/mx_ipv6.list
[[ -f $temp/mx.list ]] && rm $temp/mx.list; [[ -f $temp/net_admins ]] && rm $temp/net_admins
[[ -f $temp/net_orgs ]] && rm $temp/net_orgs; [[ -f $temp/nets ]] && rm $temp/nets
[[ -f $temp/nets ]] && rm $temp/nets4; [[ -f $temp/nets4_raw ]] && rm $temp/nets4_raw
[[ -f $temp/nets6 ]] && rm $temp/nets6; [[ -f $temp/nets6_raw ]] && rm $temp/nets6_raw
[[ -f $temp/nh_list1 ]] && rm $temp/nh_list1; [[ -f $temp/nh_list2 ]] && rm $temp/nh_list2
[[ -f $temp/nic_hdls ]] && rm $temp/nic_hdls; [[ -f $temp/nmap2.v4.txt ]] && rm $temp/nmap2.v4.txt
[[ -f $temp/nmap2.v6.txt ]] && rm $temp/nmap2.v6.txt; [[ -f $temp/nmap3.v4.txt ]] && rm $temp/nmap3.v4.txt
[[ -f $temp/nmap3.v6.txt ]] && rm $temp/nmap3.v6.txt; [[ -f $temp/nmap_output ]] && rm $temp/nmap_output
[[ -f $temp/nmap_tmp ]] && $temp/nmap_tmp; [[ -f $temp/nmap.v4.txt ]] && rm $temp/nmap.v4.txt
[[ -f $temp/nmap.v6.txt ]] && rm $temp/nmap.v6.txt; [[ -f $temp/ns4.list ]] && rm $temp/ns4.list
[[ -f $temp/nse ]] && rm $temp/nse; [[ -f $temp/ns.list ]] && rm $temp/ns.list
[[ -f $temp/ns_ipv4.list ]] && $temp/ns_ipv4.list; [[ -f $temp/ns_ipv6.list ]] && rm $temp/ns_ipv6.list
[[ -f $temp/org_ids ]] && rm $temp/org_ids; [[ -f $temp/pfx_lookups ]] && rm $temp/pfx_lookups
[[ -f $temp/pid ]] && rm $temp/pid; [[ -f $temp/pocs ]] && rm $temp/pocs
[[ -f $temp/porg ]] && rm $temp/porgs; [[ -f $temp/ports ]] && rm $temp/ports
[[ -f $temp/pov.json ]] && rm $temp/pov.json; [[ -f $temp/prefixes.list ]] && rm $temp/prefixes.list
[[ -f $temp/pwhois ]] && rm $temp/pwhois; [[ -f $temp/pwhois_table ]] && rm $temp/pwhois_table
[[ -f $temp/dns4 ]] && rm $temp/dns4; [[ -f $temp/dns6 ]] && rm $temp/dns6
[[ -f $temp/rpki.json ]] && rm $temp/rpki.json; [[ -f $temp/script_args ]] && rm $temp/script_args
[[ -f $temp/txt_ip.list ]] && rm $temp/txt_ip.list; [[ -f $temp/txt_ips_tmp ]] && rm $temp/txt_ips_tmp
[[ -f $temp/whois ]] && rm $temp/whois; [[ -f $temp/whois2 ]] && rm $temp/whois2
[[ -f $temp/whois_as ]] && rm $temp/whois_as; [[ -f $temp/whois_org ]] && rm $temp/whois_org
[[ -f $temp/whois_temp ]] && rm $temp/whois_temp; [[ -f $temp/lg.json ]] && rm $temp/lg.json
[[ -f $temp/web_ips ]] && rm $temp/web_ips; [[ -f $temp/ips_all ]] && rm $temp/ips_all
[[ -f $temp/host_dns ]] && rm $temp/host_dns
[[ -f $temp/mx4.list ]] && rm  $temp/mx4.list; [[ -f $temp/mx6.list ]] && rm $temp/mx6.list
[[ -f $temp/ns4.list ]] && rm  $temp/ns4.list; [[ -f $temp/ns6.list ]] && rm $temp/ns6.list
}

#-------------------------------  SUBMENUS  -------------------------------

f_optionsDNS(){
echo -e "   ${B}OPTIONS   >  ${C}${bold}dns)  ${D}${C}DNS\n"
echo -e "   ${B}[1]${D}  Domain DNS Records"
echo -e "   ${B}[2]${D}  ${bold}Shared ${D}Name Servers"
echo -e "   ${B}[3]${D}  Zone ${bold}Transfer${D} (AXFR/IXFR)"
echo -e "   ${B}[4]${D}  Reverse IP / Virtual Hosts (API, IPv4)"
echo -e "   ${B}[5]${D}  Run name resolution tests"
echo -e "   ${B}[6]${D}  dig ${bold}Batch Mode${D} (Mass DNS Lookup)"
echo -e "\n   ${B}[0]${D}  Back to the Global ${C}Options Menu${D}"
}

f_optionsTHREAT_INFO(){
echo -e "\n   ${B}OPTIONS   >   ${C}${bold}i)  ${D}${C}IP ADDRESS/DOMAIN REPUTATION, BANNERS, VULNERS\n"
echo -e "   ${B}[1]${D}  IPv4 Threat Report"
echo -e "   ${B}[2]${D}  Hostname/Domain Threat Report"
echo -e "   ${B}[3]${D}  IPv4 Reputation Check"
echo -e "   ${B}[4]${D}  Domain Reputation Check"
echo -e "   ${B}[5]${D}  IPv4 CVE Check (Shodan API)"
echo -e "   ${B}[6]${D}  IPv4|v6 Vulnerability Scan (Nmap)"
echo -e "\n   ${B}[0]${D}  Back to the Global ${C}Options Menu${D}"
}

f_optionsNET(){
echo -e "\n   ${B}OPTIONS   >   ${C}${bold}n)  ${D}${C}NETWORK ENUMERATION & DOCUMENTATION\n"
echo -e "\n   ${C}PUBLIC ADDRESS RANGES\n"
echo -e "   ${B}[1]${D}  Network Report                   ${B}(IPv4, IPv6)${D}"
echo -e "   ${B}[2]${D}  Ping Sweep                       ${B}(IPv4) ${R}$denied"
echo -e "   ${B}[3]${D}  Service Banners & CVEs           ${B}(IPv4, API)"
echo -e "   ${B}[4]${D}  Network DNS (rev.DNS, vHosts)    ${B}(IPv4)"
echo -e "   ${B}[5]${D}  Network Address Space"
echo -e "\n\n   ${C}PRIVATE ADDRESS RANGES (RFC1918)\n"
echo -e "  ${B}[11]${D}  Duplicates / Multihomed Systems  ${B}(IPv4)"
echo -e "  ${B}[12]${D}  Ping Sweep                       ${B}(IPv4)"
echo -e "  ${B}[13]${D}  Nmap Service- & Vulners Scan     ${B}(IPv4)"
echo -e "\n   ${B}[0]${D}  Back to the Global ${C}Options Menu${D}"
}

f_optionsRDNS(){
echo -e "${B} [1] ${C}Nmap${B}  >${D}  Simple IPv4 rDNS Lookup"
echo -e "${B} [2] ${C}Nmap${B}  >${D}  Look up IPv6 addresses for PTR records / reverse IP"
echo -e "${B} [3] ${C}Nmap${B}  >${D}  Forward confirmed rDNS / rDNS mismatches check"
[[ $opt = "4" ]] && echo -e "\n${R} [0]${D} SKIP/CANCEL" || echo -e "\n${R} [0]${D} SKIP"
}

f_optionsSSL(){
echo -e "\n   ${B}OPTIONS  >  ${C}ssl)  SSL\n"
echo -e "   ${B}[1]${D}  SSL Status & Certificates"
echo -e "   ${B}[2]${D}  SSL Status & Certificates (STARTTLS)"
echo -e "   ${B}[3]${D}  Quiet Cert Dump"
echo -e "   ${B}[4]${D}  SSL Diagnostics"
echo -e "   ${B}[5]${D}  Host / Domain Certificate Issuances (certspotter.com API)"
echo -e "\n   ${B}[0]${D}  Back to the Global ${C}Options Menu${D}"
}

f_optionsTOOLS(){
echo -e "\n   ${B}OPTIONS  >  ${C}t)  TOOLS\n"
echo -e "   ${B}[1]${D}  Abuse Contact Finder"
echo -e "   ${B}[2]${D}  Reverse Google Analytics Search"
echo -e "   ${B}[3]${D}  Shodan Geo Ping     ${B}(IPv4 only)"
echo -e "   ${B}[4]${D}  Path MTU Discovery  $denied"
echo -e "   ${B}[5]${D}  Run name resolution tests  $denied"
echo -e "   ${B}[6]${D}  DHCP & IPv6 Configs: Send DHCP Discovery Broadcast & RS Multicast"
echo -e "   ${B}[7]${D}  Dynamic Routing Protocols: Send RIP2 & OSPF Discover Broadcasts"
echo -e "   ${B}[8]${D}  Show Network Interfaces, Local IPs & Routing Tables"
echo -e "   ${B}[9]${D}  List Public IP Addresses"
echo -e "\n   ${B}[0]${D}  Back to the Global ${C}Options Menu${D}"
}

f_optionsTRACE() {
echo -e "\n   ${B}OPTIONS  >  ${C}tr)  TRACEROUTING & FIREWALK${D}  ${R}$denied\n"
echo -e "   ${B}[1]${C}  MTR${D}              RT-Times, Packet Loss, Jitter; TCP,UDP,ICMP"
echo -e "   ${B}[2]${C}  Tracepath${D}        ICMP traceroute, MTUs (non-root)"
echo -e "   ${B}[3]${C}  Dublin Tracert.${D}  NAT-aware, multipath ICMP tracerouting ${B}(IPv4 only)"
echo -e "   ${B}[4]${C}  Nmap Firewalk${D}    On-path firewall rule enumeration"
echo -e "\n   ${B}[0]${D}  Back to the Global Options ${C}Menu${D}\n"
}

f_optionsWHOIS(){
echo -e "\n   ${B}OPTIONS  >  ${C}w)  WHOIS ${D}\n"
echo -e "   ${B}[w1]${D}  ${bold}INVERSE${D} Whois                    ${B}(RIPE,AFRINIC,APNIC)"
echo -e "   ${B}[w2]${D}  ${bold}PoCs ${D}                            ${B}(ARIN,RIPE,AFRINIC,APNIC)"
echo -e "   ${B}[w3]${D}  ${bold}Netw/IP Address & AS Bulk ${D}Lookup ${B}(whois.cymru.com, whois.pwhois.org)"
echo -e "   ${B}[w4]${D}  ${bold}Domain${D} Whois Lookup"
echo -e "\n   ${B}[0]${D}  Back to the Global ${C}Options Menu${D}"
}

f_optionsWWW(){
echo -e "\n   ${B}OPTIONS  >  ${C}www)  WEB SERVERS\n"
echo -e "   ${B}[1]${D}  ${bold}Web Server Health Check${D}  ${R}$denied"
echo -e "   ${B}[2]${C}  API/cURL${D} Dump HTTP Headers"
echo -e "\n   ${B}[0]${D}  Back to the Global Options ${C}Menu${D}"
}

f_getDROPLISTS
echo ''; f_Menu
while true
do
echo -e -n "\n    ${B}?${D}    " ; read choice
[[ $option_connect = "0" ]] && denied=" (target-connect-mode only)" || denied=""
out="$temp/out"; file_date=$($DATE -I); custom_inf=""
case $choice in
#-------------------------------  RETURN TO MAIN MENU  -------------------------------
0) echo ''; f_Menu ;;
#-------------------------------  TOGGLE CONNECT/NON-CONNECT-MODES  -------------------------------
a)
echo ''; f_makeNewDir; f_Long; echo ''; denied=" (target-connect-mode only)"
f_optionsDNS | grep -v "\[0\]" > $temp/show_all
#echo '' >> $temp/show_all
f_optionsTHREAT_INFO | grep -v "\[0\]" >> $temp/show_all
#echo '' >> $temp/show_all
f_optionsNET | grep -v "\[0\]" >> $temp/show_all
#echo '' >> $temp/show_all
f_optionsSSL | grep -v "\[0\]" >> $temp/show_all
#echo '' >> $temp/show_all
f_optionsTOOLS | grep -v "\[0\]" >> $temp/show_all
#echo '' >> $temp/show_all
f_optionsTRACE | grep -v "\[0\]" >> $temp/show_all
#echo '' >> $temp/show_all
f_optionsWHOIS | grep -v "\[0\]" >> $temp/show_all
#echo '' >> $temp/show_all
f_optionsWWW | grep -v "\[0\]" >> $temp/show_all
cat $temp/show_all; denied=''; echo ''; f_removeDir; f_Menu
;;
c|con|connect) echo '' ; f_Long; f_targetCONNECT; echo ''; f_Menu ;;
#-------------------------------  CLEAR SCREEN  -------------------------------
cc|clear) clear; f_Menu ;;
#-------------------------------  ADD Permanent Output Directory  -------------------------------
s | r) f_makeNewDir; f_Long; f_REPORT; echo ''; f_targetCONNECT; f_Menu ;;
h)
f_showHELP
echo -e "${B}"; f_Long; echo -e "${C}MAIN MENU\n"
echo -e "\n  ${B}Directory      >${D}${bold}  $output_folder${D}"
echo -e "\n  ${B}TargetConnect  >  ${G}$conn\n\n"
echo -e "${B}    x)   ${D}${bold}General Target Summaries/Details (All Sources)\n"
echo -e "${C}         ASNs|AS-Sets|Hostnames|IPs|Network Addresses & Names|OrgIDs|MAC Addr."
echo -e "\n${B}  Target-specific Information Gathering & Diagnostics:\n"
echo -e "${B}    b)   ${D}${bold}BGP${D} (Prefix Status, Looking Glass)"
echo -e "${B}    d)   ${D}${bold}Domain Recon${D}"
echo -e "${B}  dns)   ${D}${bold}DNS${D}"
echo -e "${B}    i)   ${D}${bold}IPv4 & Domain Threat- & Vulnerability Data"
echo -e "${B}    n)   ${D}${bold}Networks${D}"
echo -e "${B}    t)   ${D}${bold}Tools${D}"
echo -e "${B}  ssl)   ${D}${bold}SSL${D}"
echo -e "${B}   tr)   ${D}${bold}Tracerouting, Firewalk ${D}"
echo -e "${B}    w)   ${D}${bold}Whois${D}  (inverse, PoC & bulk lookups)"
echo -e "${B}  www)   ${D}${bold}Web Servers${D}"
echo -e "\n${B}    a)   Show ALL"
echo -e "${C}    c)   Toggle TARGET - CONNECT / NON-CONNECT Mode ${B}"
echo -e "   cc)   Clear the Screen"
echo -e "    h)   Help"
echo -e "${C}    s)   Save Results ${B}"
echo -e "    q)   Quit\n"
f_Long; echo -e "${C}MAIN MENU HEADER\n"
echo -e "${B}Directory      >${D}  not saving results\n${B}Directory      >${D}  PATH/TO/DIR\n"
echo -e "${B}TargetConnect  >  ${G}true${D}\n${B}TargetConnect  >  ${R}false${D}\n"
echo -e "The ${G}Directory >${D} - field shows the location, any script output is written to."
echo -e "\nTo save script output, chose option s) and enter directory name and path."
echo -e "\nThe ${G}TargetConnect >${D} - field indicates if packets are send from your IP-address to target systems."
echo -e "If set to false, only third party resources are queried."
echo -e "\nUse option ${B}c)${D} to toggle ${B}TARGET - CONNECT ${D} or ${B} NON-CONNECT ${D}${bold}MODES${D}"
#echo -e "${B}"; f_Long; echo -e "\nDRWHO.SH  VERS. 4.0  (NOV, 2023)\n"; f_Long
echo -e "${B}"; f_Long;
echo -e "${C}\nUSE CASES\n\n"
echo -e " 1. Information Gathering${D}\n"
echo -e "\n${B}  1.1 Dokument an organization's IT infrastructure & service provider relationships:${D}"
echo -e "\n      1. Domains: d) Domain Recon"
echo -e "\n      2. ASNs: Select option x) & choose [2] details"
echo -e "\n\n${B}  1.2 DNS, Whois & Geolocation Data for Hosts & Networks${D}"
echo -e "\n      - General information (networks, IP addresses & hostnames): -> Option x)"
echo -e "\n      - Detailed network reports: -> Option n) -> [1]"
echo -e "\n\n${B}  1.3 Threat Intelligence & Reputation Data for Hosts${D}"
echo -e "\n      -> Option i)"
echo -e "\n\n${B}  1.4 Domain Whois & DNS Records${D}"
echo -e "\n      -> Option dns) -> [1] (Whois & detailed DNS resource record information)"
echo -e "\n      -> Option dns) -> [2] Domains sharing a given name server"
echo -e "\n      -> Option w) -> [4] Domain Whois records"
echo -e "\n\n${B}  1.5 Discover IP Address Ranges${D}"
echo -e "\n      - Suballocations & Assignments within less specific network resources"
echo -e "\n        ARIN & RIPE: -> Option n) -> [1] Network Report -> [1]"
echo -e "\n        RIPE, APNIC & AFRINIC: -> Option n) -> [4]"
echo -e "\n      - Global search by network name:"
echo -e "\n        -> Option x)"
echo -e "\n        Searches AFRINIC, APNIC, ARIN & RIPE databases"
echo -e "\n        Provides context information to help assess network ownership"
echo -e "\n      - Inverse Whois search:"
echo -e "\n        -> Option w) -> [w1]"
echo -e "\n        Returns all network resources associsted with a given Org/Abuse/Admin/Tech/Maintainer object"
echo -e "\n        Expected input for RIPE, APNIC & AFRINIC searches: Type of nic-hdl object + ; + object handle (ID)"
echo -e "\n        Expected input for ARIN searches: Org- or Customer ID"
echo -e "\n\n${B}  1.6 Autonomous System Report${D}"
echo -e "\n        -> Option x) -> [1] Details"
echo -e "\n        AS status, organization & contact, statistics, peering policies, IX presences, AS sets, announced prefixes & peers"
echo -e "\n\n${C}2. DIAGNOSTICS${D}\n"
echo -e "\n${C}  2.1 DOMAIN DNS RESOURCE RECORDS${D}\n"
echo "    - Queries all common types of DNS records,"
echo "    - TTL in milliseconds and readable time units"
echo "    - Domain Whois in standard format, IP Whois information in tabular overview"
echo -e "\n${B}  RFC 1912 Best Practices Check${D}\n"
echo "    - Forward-confirmed Reverse DNS"
echo "    - CNAME records for NS & MX (not ok)"
echo "    - SOA: RFC 1912 recommendations for refresh, retry & expire"
echo "    - NS: Checks for the possibility of recursive lookups"
echo "    - NS: Match zone serials on all servers"
echo "    - MX: Warning for missing PTR records for MX servers"
echo -e "\n${B}  Availability${D}\n"
echo "    - MX: SMTP banner (netcat), TCP & ICMP ping if no response"
echo "    - NS: Determination of response time (dig +nssearch), TCP & ICMP ping if no response"
echo "    - SRV: TCP & ICMP ping"
echo "    - Hosts: HTTP response time (redirects & total), ICMP ping"
echo "    - All: Routing status of prefixes"
echo -e "\n${B}  Integrity & Security${D}\n"
echo "    - SSL status of domain hosts & MX servers"
echo "    - DNSSec signature"
echo "    - CAA records & SPF"
echo "    - MX records SPAM blocklist check"
echo "    - Prefixes ROA status"
echo "    - Information disclosure vulnerabilities:"
echo "    - Unnecessary DNS records such as hinfo & version.bind"
echo "    - Optional: Zone transfer"
echo "    - Optional: Evaluation of ciphersuites & DH parameters for domain hosts & MX records"
echo "    - Optional: Service banners & CVEs for all DNS records (shodan.io)"
echo -e "\n${C}  2.2 CONNECTIVITY & ROUTING ISSUES${D}\n"
echo "    Common suspects for connection problems in public networks include:"
echo "    DNS, BGP, congestion and bottlenecks, and, occasionally, MTU settings"
echo -e "\n${B}    2.2.1 DNS name resolution${D}\n"
echo -e "    - Full name resolution (forward-confirmed RDNS) via API AND system default\n     nameservers, tracing of the DNS lookup process and authoritative name servers"
echo -e "\n${B}    2.2.2 BGP & Tracerouting${D}\n"
echo -e "    - Tracerouting (MTR and/or Tracepath) with additional information for all hops:\n"
echo "     Prefix Visibility & ROA Status, Hop DNS & Geolocation, AS Organization & Abuse Contact,"
echo "     detection of bogon addresses, internet nodes (IX) & tor nodes (inspired by nitefood's fancy 'asn' project)"
echo "     -> Option tr) [1], [2]"
echo -e "\n${B}    2.2.3 Other Routing Protocols & DHCP${D}\n"
echo -e "\n    - Local routing and DHCP configurations can be checked by sending RIP2, OSPF and DHCP discover broadcasts,"
echo "      Router Solicitation multicasts, and by listing routing tables, interface statistics & public IP addresses"
echo "     -> Option t) -> [6] - [9]"
echo -e "\n${B}    2.2.3 MTU Discovery${D}\n"
echo "     -> Option t) -> [4]"
echo -e "\n${B}    2.2.4 Ping Sweep${D}\n"
echo "     -> Option n) ->  [2] for public and [12] for local networks"
echo -e "\n${C}  2.3 WEBSERVER HEALTH CHECK${D}"
echo "     -> Option www) ->  [1]"
echo -e "${B}"; f_Long; echo -e "${C}\nSOURCES${D}\n\n"
echo -e "${B}APIs${D}\n"
echo -e "abusix.com, certspotter.com, greynoise.io, hackertarget.com, ip-api.com, SANS Internet Storm Center (isc.sans.edu)"
echo -e "otx.alienvault.com, peeringdb.com, projecthoneypot.org, rapiddns.io,"
echo -e "ripeSTAT Data API (https://stat.ripe.net), shodan.io, stopforumspam.org, urlscan.io\n"
echo -e "\n${B}Threat Feeds & DNS Blocklists${D}\n"
echo -e "Amnesty Tech Spyware Domains (raw.githubusercontent.com/AmnestyTech), barracudacentral.org, blocklist.de,\ncinsscore.com/list/ci-badguys.txt, dronebl.org, feodotracker.abuse.ch, fullbogons.cymru.com, \ngithub.com/rblaine95/monero-banlist, ix.dnsbl.manitu.net, kundenserver.de,\nmsrbl.net, openphish.com/feed.txt, phishing.army, s5h.net, reputation.alienvault.com, rescure.me, \nsorbs.net, spamcop.net, spamrats.com, Spamhaus Don't Route Or Peer DROP (spamhaus.org/drop), \ntalosintelligence.com, tor.dan.me.uk, tornevall.org, urlhaus malware domains (malware-filter.gitlab.io), zonefiles.io\n"
echo -e "\n${B}Whois Servers${D}\n"
echo -e "whois.cymru.com, whois.pwhois.org \nRIR whois Servers (whois.afrinic.net, whois.apnic.net, whois.arin.net, whois.lacnic.net, whois.ripe.net)"
echo ''; f_Menu
;;
b|bgp)
f_makeNewDir; domain_enum="false"; f_Long; target_type="prefix"; rir=""; x=""
echo -e "${B}\nBGP STATUS  -  ${C} Expected input:${D}${bold} IPv4|v6 Address or Prefix ${D}"
echo -e -n "\n${B}Options  >  [1]${D}  Set target  ${B}| [2]${D}  Target list  ${B}| [0]${D}  Back to the ${B}main menu ?${D}  " ; read -r option_target
if [ $option_target != "0" ]; then
  f_setTARGET; f_get_IX_PFX
  for t in $(cat $temp/targets.list); do
    f_CLEANUP_FILES; f_getTYPE "$t"
    if [ $net_type = "cidr" ] || [ $host_type = "ip" ]; then
      if [ "$bogon" = "TRUE" ]; then
        f_BOGON_INFO "$t"
      else
        check_ixlan=$(grep -w -c "$t" ${PWD}/${file_date}.ix_pfx.txt)
        if [[ $check_ixlan  -gt 0 ]]; then
          echo -e "\nIX peering LAN detected. Not a BGP resource, aborting ...\n"
        else
          if [ $host_type = "ip" ]; then
            $CURL -m 10 -s --location --request GET "https://stat.ripe.net/data/network-info/data.json?resource=$t" > $temp/net.json
            net_prefix=$($JQ '.data.prefix?' $temp/net.json | head -1); [[ -n "$net_prefix" ]] && x="$net_prefix"
            $CURL -m 10 -s --location --request GET "https://stat.ripe.net/data/prefix-overview/data.json?resource=$x" > $temp/pov.json
          fi
          if [ $net_type = "cidr" ]; then
            $CURL -m 10 -s --location --request GET "https://stat.ripe.net/data/prefix-overview/data.json?resource=$t" > $temp/pov.json
            announced=$($JQ '.data.announced' $temp/pov.json)
            if [ $announced = "false" ]; then
              num_related=$($JQ '.data.actual_num_related' $temp/pov.json)
              num_filtered=$($JQ '.data.num_filtered_out' $temp/pov.json)
              related_pfx=$($JQ '.data.related_prefixes[]' $temp/pov.json | sed '/null/d')
              echo -e "\nPrefix is not announced or has very low visibility.\n"
              [[ -n "$related_pfx" ]] && echo -e "\nRELATED\n\nNum related: $num_related (actual), $num_filtered (low vis.)\n\n$related_pfx" | tee -a ${out}
              $CURL -m 10 -s --location --request GET "https://stat.ripe.net/data/network-info/data.json?resource=$t" > $temp/net.json
              net_prefix=$($JQ '.data.prefix?' $temp/net.json | head -1); [[ -n "$net_prefix" ]] && x="$net_prefix"
            else
              x=$($JQ '.data.resource' $temp/pov.json)
            fi
          fi # net_type = cidr
        fi # target is not an IX peering LAN
      fi # target not a Bogon address
    fi # target is an IP or CIDR network address
    if [ -n "$x" ]; then
      file_name=$(echo $x | tr ':' '.' | tr '/' '_' | tr -d ' ')
      out="${outdir}/BGP_STATUS.${file_date}_${file_name}.txt"
      x_asn=$($JQ '.data.asns[0].asn' $temp/pov.json)
      f_HEADLINE3 "[BGP]   PREFIX STATUS  -  $x  -  $(date -R)" | tee -a ${out}
       f_PREFIX "$x" | tee -a ${out}
       #f_ROUTE "$x" | tee -a ${out}
       f_BGP_UPDATES "$x" | tee -a ${out}
      if [ -f $temp/routing_consistency ]; then
        f_HEADLINE2 "RELATED RESOURCES: RIS-WHOIS CONSISTENCY\n"; cat $temp/routing_consistency
      fi
      echo ''; f_Long
      echo -e "\n${B}Option  >${C}  RIPEstat Looking Glass\n"
      echo -e "${B} [1] ${D} Query looking glass for $x"
      echo -e "${R} [0] ${D} SKIP"; echo -e -n "\n${B}  ? ${D}  " ; read -r opt_lg
      if [ $opt_lg = "1" ]; then
        out="${outdir}/LGLASS.${file_date}_${file_name}.txt"
        $CURL -s -m 10 --location --request GET "https://stat.ripe.net/data/looking-glass/data.json?resource=${x}" > $temp/lg.json
        f_HEADLINE3 "[BGP]   LOOKING GLASS (RIPEstat)  -  $x  (AS $x_asn)  -  $(date -R)" | tee -a ${out}
        echo -e "\n${B}Options  >  ${C}Select Ripe Route Collector Locations\n"
        echo -e "${B} ae)${D}  AE - RRC26 @UAE-IX, Dubai"
        echo -e "${B} de)${D}  DE - RRC12 @DE-CIX, Frankfurt"
        echo -e "${B} fr)${D}  FR - RRC02 @SFINX / RRC21 @France-IX, Paris"
        echo -e "${B} jp)${D}  JP - RRC06 @DIX-IE, Tokyo"
        echo -e "${B} n1)${D}  NL - RRC00 @RIPE-NCC Multihop, Amsterdam"
        echo -e "${B} n2)${D}  NL - RRC03 @AMS-IX/NL-IX, Amsterdam "
        echo -e "${B} ru)${D}  RU - RRC13 @MSK-IX, Moscow"
        echo -e "${B} sg)${D}  SG - RRC23 @Equinix SG, Singapore"
        echo -e "${B} uk)${D}  UK - RRC01 @LINX/LONAP, London"
        echo -e "${B} u1)${D}  US - RRC08 @MAE-WEST, San Jose CA"
        echo -e "${B} u2)${D}  US - RRC11 @NYIIX, New York City NY"
        echo -e "${B} uy)${D}  UY - RRC24 @LACNIC Multihop, Montevideo"
        echo -e "${B} za)${D}  ZA - RRC19 @NAP Africa JB  Johannesburg"
        echo -e -n "\n${B}SET  > ${C}RCC Locations ${D}  -  e.g.  de uk n1 u1  ${B}>>${D}  " ; read rcc_input_raw
        rcc_input=$(echo "$rcc_input_raw" | sed 's/\,/ /g')
        if echo $rcc_input | grep -q 'ae'; then
          collector="RRC26  @UAE-IX - Dubai, UAE"; f_printLG "$($JQ '.data.rrcs[] | select (.rrc=="RRC26") | .peers[] | {PFX: .prefix, ASN: .asn_origin, ASPath: .as_path, Origin: .origin, Community: .community, NextHop: .next_hop}' $temp/lg.json)" | tee -a ${out}
        fi
        if echo $rcc_input | grep -q 'de'; then
          collector="RRC12  @DE-CIX - Frankfurt, Germany"; f_printLG "$($JQ '.data.rrcs[] | select (.rrc=="RRC12") | .peers[] | {PFX: .prefix, ASN: .asn_origin, ASPath: .as_path, Origin: .origin, Community: .community, NextHop: .next_hop}' $temp/lg.json)" | tee -a ${out}
        fi
        if echo $rcc_input | grep -q 'fr'; then
          collector="RRC02  @SFINX - Paris, France"; f_printLG "$($JQ '.data.rrcs[] | select (.rrc=="RRC02") | .peers[] | {PFX: .prefix, ASN: .asn_origin, ASPath: .as_path, Origin: .origin, Community: .community, NextHop: .next_hop}' $temp/lg.json)" | tee -a ${out}
          collector="RRC21  @France-IX - Paris, France"; f_printLG "$($JQ '.data.rrcs[] | select (.rrc=="RRC21") | .peers[] | {PFX: .prefix, ASN: .asn_origin, ASPath: as_path, Origin: .origin, Community: .community, NextHop: .next_hop}' $temp/lg.json)" | tee -a ${out}
        fi
        if echo $rcc_input | grep -q 'jp'; then
          collector="RRC06  @DIX-IE - Tokyo, Japan"; f_printLG "$($JQ '.data.rrcs[] | select (.rrc=="RRC06") | .peers[] | {PFX: .prefix, ASN: .asn_origin, ASPath: .as_path, Origin: .origin, Community: .community, NextHop: .next_hop}' $temp/lg.json)" | tee -a ${out}
        fi
        if echo $rcc_input | grep -q 'n1'; then
          collector="RRC00  @RIPE-NCC Multihop - Amsterdam, NL"; f_printLG "$($JQ '.data.rrcs[] | select (.rrc=="RRC00") | .peers[] | {PFX: .prefix, ASN: .asn_origin, ASPath: .as_path, Origin: .origin, Community: .community, NextHop: .next_hop}' $temp/lg.json)" | tee -a ${out}
        fi
        if echo $rcc_input | grep -q 'n2'; then
          collector="RRC03  @AMS-IX/NL-IX - Amsterdam, NL"; f_printLG "$($JQ '.data.rrcs[] | select (.rrc=="RRC03") | .peers[] | {PFX: .prefix, ASN: .asn_origin, ASPath: .as_path, Origin: .origin, Community: .community, NextHop: .next_hop}' $temp/lg.json)" | tee -a ${out}
        fi
        if echo $rcc_input | grep -q 'ru'; then
          collector="RRC13  @MSK-IX - Moscow, Russian Federation"; f_printLG "$($JQ '.data.rrcs[] | select (.rrc=="RRC13") | .peers[] | {PFX: .prefix, ASN: .asn_origin, ASPath: .as_path, Origin: .origin, Community: .community, NextHop: .next_hop}' $temp/lg.json)" | tee -a ${out}
       fi
       if echo $rcc_input | grep -q 'sg'; then
         collector="RRC23  @Equinix SG - Singapore"; f_printLG "$($JQ '.data.rrcs[] | select (.rrc=="RRC23") | .peers[] | {PFX: .prefix, ASN: .asn_origin, ASPath: .as_path, Origin: .origin, Community: .community, NextHop: .next_hop}' $temp/lg.json)" | tee -a ${out}
       fi
       if echo $rcc_input | grep -q 'uk'; then
         collector="RRC01  @LINX/LONAP - London, UK"; f_printLG "$($JQ '.data.rrcs[] | select (.rrc=="RRC01") | .peers[] | {PFX: .prefix, ASN: .asn_origin, ASPath: .as_path, Origin: .origin, Community: .community, NextHop: .next_hop}' $temp/lg.json)" | tee -a ${out}
       fi
       if echo $rcc_input | grep -q 'u1'; then
         collector="RRC08  @MAE-WEST - San Jose, California, US"; f_printLG "$($JQ '.data.rrcs[] | select (.rrc=="RRC08") | .peers[] | {PFX: .prefix, ASN: .asn_origin, ASPath: .as_path, Origin: .origin, Community: .community, NextHop: .next_hop}' $temp/lg.json)" | tee -a ${out}
       fi
       if echo $rcc_input | grep -q 'u2'; then
         collector="RRC11  @NYIIX - New York City, New York, US"; f_printLG "$($JQ '.data.rrcs[] | select (.rrc=="RRC11") | .peers[] | {PFX: .prefix, ASN: .asn_origin, ASPath: .as_path, Origin: .origin, Community: .community, NextHop: .next_hop}' $temp/lg.json)" | tee -a ${out}
       fi
       if echo $rcc_input | grep -q 'uy'; then
         collector="RRC24  @LACNIC Multihop - Montevideo, Uruguay"; f_printLG "$($JQ '.data.rrcs[] | select (.rrc=="RRC24") | .peers[] | {PFX: .prefix, ASN: .asn_origin, ASPath: .as_path, Origin: .origin, Community: .community, NextHop: .next_hop}' $temp/lg.json)" | tee -a ${out}
       fi
       if echo $rcc_input | grep -q 'za'; then
          collector="RRC19  @NAP Africa JB - Johannesburg, South Africa"; f_printLG "$($JQ '.data.rrcs[] | select (.rrc=="RRC19") | .peers[] | {PFX: .prefix, ASN: .asn_origin, ASPath: .as_path, Origin: .origin, Community: .community, NextHop: .next_hop}' $temp/lg.json)" | tee -a ${out}
       fi
     fi
   fi
  done
fi
echo ''; unset rir; unset target_type; f_removeDir; f_Menu
;;
#-------------------------------  DNS  -------------------------------
dns|mx|ns|zone|zonetransfer|dig|nslookup|nsec)
f_makeNewDir; f_Long; f_optionsDNS; echo -e -n "\n    ${B}?${D}   " ; read option_dns
if ! [ $option_dns = "0" ]; then
  domain_enum="false"; target_type="dnsrec"; quiet_dump="false"; option_testssl="0"
  declare -a dig_array=()
  #************** DOMAIN DNS RECORDS *******************
  if [ $option_dns = "1" ]; then
    option_starttls="0"; tls_port="443"; ssl_details="false"; f_getTHREAT_FEEDS_IP
    echo -e -n "\n${B}Target  >  [1]${D}  Set Target  ${B}|  [2]${D}  Read from file  ${B}?${D}  " ; read -r option_target
    f_setTARGET
    dig_array+=(+noall +answer +noclass +ttlid)
    echo -e "\n${B}DNS Records >  ${C}Options${D}\n\n"
    echo -e "${B} 1${D}  Check zone for RFC1912 best practices  $denied"
    echo -e "${B} 2${D}  Check for unauthorized zone transfers"
    echo -e "\n${B} 3${D}  DNS Records IP Address Details"
    echo -e "${B} 4 ${D} MX Banners  $denied"
    echo -e "${B} 5${D}  Domain Host & MX SSL Diagnostics  $denied"
    echo -e "\n${B} 6${D}  Domain Host & SRV Records: ICMP & TCP Ping  $denied"
    echo -e "${B} 7${D}  IP Address Reputation Check"
    echo -e -n "\n${B}Set  > ${C}DNS Options ${D} - e.g. 1,3 - leave empty to skip  ${B}>>${D}  " ; read dns_options_input
    dns_options=$(echo "$dns_options_input" | sed 's/,/  /g' )
    [[ $(grep -oc "1" <<< $dns_options) -gt 0 ]] && [[ $option_connect != "0" ]] && rfc1912="true" || rfc1912="false"
    [[ $(grep -oc "2" <<< $dns_options) -gt 0 ]] && option_axfr="y" || option_axfr="n"
    [[ $(grep -oc "3" <<< $dns_options) -gt 0 ]] && dns_rr_details="true" || dns_rr_details="false"
    [[ $(grep -oc "4" <<< $dns_options) -gt 0 ]] && [[ $option_connect != "0" ]] && mx_banners="true" || mx_banners="false" 
    [[ $(grep -oc "5" <<< $dns_options) -gt 0 ]] && [[ $option_connect != "0" ]] && ssl_diag="true" || ssl_diag="false"
    [[ $(grep -oc "7" <<< $dns_options) -gt 0 ]] && check_reputation="true" || check_reputation="false"
    if [[ $(grep -oc "6" <<< $dns_options) -gt 0 ]] && [ $option_connect != "0" ]; then
      send_ping="true"
      default_ttl=$($PING -c 1 127.0.0.1 | grep -so "ttl=.[0-9]${2,3}" | cut -s -d '=' -f 2 | tr -d ' ')
    else
      send_ping="false"
    fi
    if [ -f $temp/targets_name ]; then
      for x in $(f_EXTRACT_HOSTN "$temp/targets_name" | sort -u); do
        f_getTYPE "$x"; f_WHOIS_STATUS "$x" > $temp/whois_status
        if [ -f $temp/whois_status ] && [[ $(grep -c "^Domain:" $temp/whois_status) -gt 0 ]]; then
          if [ $option_connect = "0" ]; then
            webpresence="false"
          else
            curl_ua="-A $ua_moz"; out="${outdir}/DNS_RECORDS.$file_date_$x.txt"
            error_code=6; f_CURL_WRITEOUT "$x"; echo ''; f_Long
            if [ $? = ${error_code} ]; then
              webpresence="false"; echo -e "${R}$x  WEBSITE CONNECTION: FAILURE${D}\n"
            else
              webpresence="true"; echo -e "$x WEBSITE CONNECTION: ${G} SUCCESS${D}"
            fi
          fi
          f_DNS_RR "$x" | tee -a ${out}
          [[ $dns_rr_details = "true" ]] && f_RECORD_DETAILS | tee -a ${out}
          if [ $option_connect != "0" ]; then
            if [ $ssl_diag = "true" ]; then
              option_starttls="0"; declare ssl_array1; ssl_array1+=(-servername $x -verify_hostname $x)
              f_CERT_INFO "$x" | tee -a ${out}; unset ssl_array1
              if [ -f $temp/mx_hosts ]; then
                option_starttls="1"; starttls_pro="smtp"
                for m in $(cat $temp/mx_hosts); do
                  declare ssl_array1; declare ssl_array2; ssl_array1+=(-servername $m -verify_hostname $m); ssl_array2+=(-servername $m)
                  f_CERT_INFO "$m"; unset ssl_array1; unset ssl_array2
                done | tee -a ${out}
              fi
            fi
          fi
          if [ $check_reputation = "true" ]; then
            f_HEADLINE "DNS RECORDS | IP REPUTATION LOOKUP" | tee -a ${out}
            for i in $(cat $temp/dns4 | sort -uV); do f_IP_REPUTATION2 "$i"; done | tee -a ${out}
          fi
        else
          echo "No valid target domain found for $h"
        fi
      done
    else
      echo -e "\nInvalid target\n"
    fi
  #************** SHARED NAME SERVERS *******************
  elif [ $option_dns = "2" ] ; then
    echo -e -n "\n${B}Shared NS  > Target  >${C} NAME SERVER  ${B}>>${D}  " ; read targetNS ; echo ''
    out="${outdir}/SharedNameserver_${targetNS}.txt" ; echo '' | tee -a ${out}
    $CURL -s "https://api.hackertarget.com/findshareddns/?q=${targetNS}${api_key_ht}" > $temp/sharedns
    f_HEADLINE "$targetNS  |  SHARED NS  ($file_date)" | tee -a ${out}
    echo -e "DOMAINS: $(wc -l < $temp/sharedns)\n\n" | tee -a ${out}
    if [[ $(wc -l < $temp/sharedns) -gt 700 ]] ; then
      cat $temp/sharedns | tee -a ${out}
    else
      echo -e "Resolving results...\n"
      $DIG +noall +answer +noclass +nottlid -f $temp/sharedns > $temp/sharedns_hosts
      grep 'A' $temp/sharedns_hosts | sed '/NS/d' | sed '/CNAME/d' | awk '{print $1,"\n\t\t\t\t\t\t",$3}'
      f_EXTRACT_IP4 "$(grep 'A' $temp/sharedns_hosts)" > $temp/ips_sorted
      if [[ $( wc -l < $temp/ips_sorted) -lt 101 ]] ; then
        cat $temp/ips_sorted > $temp/ips_sorted.list
      else
        cat $temp/ips_sorted | sort -t . -k 1,1n -k 2,2n -k 3,3n -u > $temp/ips_sorted.list
      fi
      echo '' | tee -a ${out}; f_WHOIS_TABLE "$temp/ips_sorted.list" tee -a ${out}
    fi
  #************** ZONE TRANSFER *******************
  elif [ $option_dns = "3" ]; then
    unset target_ns; unset target_dom; echo -e -n "${B}\nZONE TRANSFER  > ${C} Expected input:${D}${bold}Domain name${D}\n"
    if [ $option_connect = "0" ]; then
      option_xfr="1"
    else
      echo -e "\n${B}Options  > ${C}Zone transfer${B}\n"
      echo -e " ${B}[1] ${C} API  ${B} Full Zone Transfer${D}         (probes all NS records)"
      echo -e " ${B}[2] ${C} $DIG  ${B} Full Zone Transfer${D}         (probes all or specific name servers)"
      echo -e " ${B}[3] ${C} $DIG  ${B} Incremental Zone Transfer${D}  (probes specific name servers)"
      echo -e -n "\n${B}  ? ${D}  " ; read option_xfr
    fi
    echo -e -n "\n${B}Target >${C}  Domain  ${B}>>${D}  " ; read target_dom
    if [ $option_xfr = "1" ]; then
      out="${outdir}/AXFR_API.${file_date}_${target_dom}.txt"; f_AXFR "$target_dom" | tee $temp/ztrans_results
    else
      [[ $report = "true" ]] && echo -e -n "\n${B}Output > ${C}OUTPUT - FILE NAME ${B}>>${D}  " ; read filename; out=${outdir}/$filename.txt
      dns_lod="1"; nssrv_dig="@1.1.1.1"; declare dig_array; dig_array+=( @1.1.1.1 +noall +answer +noclass +ttlid); echo ''
      f_NS "$target_dom" | tee -a $temp/ztransfer; f_SOA "$target_dom" | tee -a $temp/ztransfer; f_Long | tee -a $temp/ztransfer
      if [ $option_xfr = "3" ]; then
        option_ns="2"; xfr_type='IXFR'; echo -e -n "\n${B}Set    >  ${C}Zone serial  ${B}>>${D}  " ; read serial_input
        zserial=$(echo $serial_input | tr -d ' ')
      else
        xfr_type='AXFR'
        echo -e -n "\n\n${B}TARGET NS > [1]${D} Probe all NS records ${B}| [2]${D} Specific name server  ${B}?${D}  " ; read option_ns
      fi
      if [ $option_ns = "2" ] ; then
        echo -e -n "\n${B}Set    >  ${C}Target name server  ${B}>>${D}  " ; read target_ns
        f_HEADLINE "$xfr_type  |  $target_dom,  $target_ns" | tee -a ${out}
        if [ $option_xfr = "3" ]; then
          $DIG ixfr=${zserial} +noall +answer +stats $target_dom @${target_ns} | sed '/;; Query time:/{x;p;x;}' |
          sed '/server found)/G' | tee $temp/ztrans_results
        else
          $DIG axfr @${target_ns} +noall +answer +stats $target_dom | sed '/;; Query time:/{x;p;x;}' |
          sed '/server found)/G' | tee $temp/ztrans_results
        fi
      else
        f_HEADLINE "AXFR  |  $target_dom" | tee -a ${out}
        for i in $(cat $temp/ns_servers); do
          $DIG axfr @${i} +noall +answer +stats $target_dom | sed '/;; Query time:/{x;p;x;}' | sed '/server found)/G'
        done | tee $temp/ztrans_results
      fi
      cat $temp/ztransfer >> ${out}; echo '' >> ${out}
    fi
    if [ -f $temp/ztrans_results ]; then
      cat $temp/ztrans_results >> ${out}; f_EXTRACT_IP4 "$temp/ztrans_results" > $temp/ips_sorted1
      if [ -f $temp/ips_sorted1 ] && [[ $(wc -w < $temp/ips_sorted1) -gt 3 ]]; then
        for ip in $(cat $temp/ips_sorted1); do f_BOGON "$ip"; [[ $bogon = "TRUE" ]] || echo $ip >> $temp/no_bogons; done
        if [ -f $temp/no_bogons ]; then
          sort -t . -k 1,1n -k 2,2n -u $temp/no_bogons > $temp/ips_sorted2
          f_HEADLINE2 "PUBLIC IP ADDRESSES\n\n" | tee -a ${out}; no_bogons=$(f_printADDR "$temp/no_bogons")
          echo "$no_bogons" | sed 's/ /  /g' | sed G | tee -a ${out}; f_WHOIS_TABLE "$temp/ips_sorted2" | tee -a ${out}
        fi
      fi
    fi
  elif [ $option_dns = "4" ] ; then
    echo -e -n "\n${B}Target  >  [1]${D}  Set Target  ${B}|  [2]${D}  Read from file  ${B}?${D}  " ; read -r option_target
    f_setTARGET; target_type="default"
    if [ -f $temp/targets_host4 ]; then
      for x in $(cat $temp/targets_host4); do
        out="${outdir}/REV_IP.${x}.txt"
        f_VHOSTS "$x"; cat $temp/vhosts_out
      done | tee -a ${out}
    else
      echo -e "\nPlease supply a valid hostname\n"
    fi

elif [ $option_dns = "5" ] ; then
  echo -e -n "\n${C}Target  ${B}>>${D}  " ; read x
  f_getTYPE "$x"
  if [ $host_type = "hostname" ] || [ $host_type = "ip" ]; then
    f_DNS_DIAG "$x"
  else
    echo -e "\nInvalid target type\n"
  fi
  #************** DIG BATCH MODE (DNS MASS LOOKUP) *******************
  elif [ $option_dns = "6" ] ; then
    echo -e -n "${B}\nDIG BATCH MODE > ${C} Expected input:${D}${bold}File containing host-/domain names${D}\n"
    echo -e "\n${B}Options  > $DIG >${C} Record Types\n"; echo -e "${B} [1]${D} A"; echo -e "${B} [2]${D} AAAA"
    echo -e "${B} [3]${D} NS"; echo -e "${B} [4]${D} MX"; echo -e "${B} [5]${D} SRV";  echo -e -n "\n${B}  ? ${D}  " ; read option_rr
    echo -e -n "\n${B}INPUT FILE >${C} Path to file  ${B}>>${D}  " ; read input
    if [ $report = "true" ]; then
      echo -e -n "\n${B}OUTPUT FILE >${C} Path to file  ${B}>>${D}  " ; read output; out="${outdir}/${output}.${file_date}.txt"
    fi
    [[ $option_rr = "1" ]] && record="A"; [[ $option_rr = "2" ]] && dig_array+=(aaaa); record="AAAA"
    [[ $option_rr = "3" ]] && dig_array+=(ns); record="NS"; [[ $option_rr = "4" ]] && dig_array+=(mx); record="MX"
    [[ $option_rr = "5" ]] && dig_array+=(srv); record="SRV"; dig_array+=(+noall +answer +noclass +ttlid)
    f_HEADLINE "DIG BATCH MODE | RECORD TYPE: $record | $file_date" | tee -a ${out}
    $DIG ${dig_array[@]} -f ${input} | tee -a ${out} ; echo '' | tee -a ${out}
  fi # option_dns = ?
  unset target_type; unset x; echo ''
fi #  option_dns != 0
f_removeDir; f_Menu
;;
#-------------------------------  DOMAIN RECON / SUBDOMAINS  -------------------------------
d|domain|recon)
f_makeNewDir; target=""; x=""; target_type="domain"
f_Long;  echo -e -n "\n${B}Options  >  [1]${D}  Set target  ${B}| [0]${D}  Back to the ${B}main menu ?${D}  " ; read -r option_target
if [ $option_target != "0" ]; then
  echo -e -n "\n${B}Target  >  ${C}DOMAIN  ${B}>>${D}  " ; read domain_input
  # validate input
  if [ -n "$domain_input" ]; then
    domain_enum="true"; x=$(f_EXTRACT_HOSTN "$domain_input")
   [[ -n "$x" ]] && f_WHOIS_STATUS "$x" > $temp/whois_status && f_getTYPE "$x"
  fi
fi
if [ -f $temp/whois_status ] && [[ $(grep -c "^Domain:" $temp/whois_status) -gt 0 ]]; then
  send_ping="false"; option_detail="1"; target_cat="hostname"
  dig_array+=(+noall +answer +noclass +nottlid); echo $x > $temp/hosts
  out="${outdir}/DOMAIN_${x}.${file_date}.txt"; option_whois="y"
  echo -e "\n${B}Options  ${C}>  Subdomain Hosts, Service Provider Contacts\n"
  echo -e "${B} [1]${D}  Get geolocation & service info for subdomain hosts (max. IP count = 100)"
  echo -e "${B} [2]${D}  Look up service provider whois details"
  echo -e "${B} [3]${D}  BOTH"
  echo -e "\n${R} [0]${D}  SKIP"
  echo -e -n "\n${B}   ?${D}  " ; read -r option_domain1
  if [ $option_domain1 = "1" ] || [ $option_domain1 = "3" ]; then
    subdomain_host_details="true"
  else
    subdomain_host_details="false"
  fi
  if [ $option_domain1 = "2" ] || [ $option_domain1 = "3" ]; then
    isp_contacts="true"
  else
    isp_contacts="false"
  fi
  if [ $option_connect = "0" ]; then
    webdata="false"
    echo -e -n "\n${B}Option   >  ${C}Zone Transfer (API)  ${B}> ${D} Attempt zone transfers   ${B}[y] | [n] ?${D}  " ; read -r option_axfr
  else
    echo -e "\n${B}Options  ${C}>  Website, AXFR\n"
    echo -e "${B} [1]${D}  Domain webpresence details"
    echo -e "${B} [2]${D}  Attempt zone transfers (API)"
    echo -e "${B} [3]${D}  BOTH"
    echo -e "\n${R} [0]${D}  SKIP"
    echo -e -n "\n${B}   ?${D}  " ; read -r option_domain2
    if [ $option_domain2 = "2" ] || [ $option_domain2 = "3" ]; then
      option_axfr="y"
    else
      option_axfr="n"
    fi
    if [ $option_domain2 = "1" ] || [ $option_domain2 = "3" ]; then
      webdata="true"; page_details="true"; send_ping="false"; option_web_test="0"
      echo -e "\n${B}Options >${C} WhatWeb Website Data${B}\n"
      echo -e " ${B}[1]${D}  hackertarget.com API"
      echo -e " ${B}[2]${D}  Local App"
      echo -e " ${R}[0]${D}  SKIP"; echo -e -n "\n${B}   ?${D}  "; read -r ww_source
      [[ $ww_source = "0" ]] && ww="false" || ww="true"
    else
      webdata="false"
    fi
  fi
  echo -e "\n${B}Options  ${C}>  Hosting Provider Networks\n"
  echo -e " ${B}[1]${D}  Ignore hosting provider networks when searching for global resources"
  echo -e " ${B}[0]${D}  Don't ignore hosting provider networks (recommended, if target is a hosting provider)"
  echo -e -n "\n${B}   ?${D}  "; read -r ignore_hosting
  #************** Start **************
  f_HEADLINE3 "[DOMAIN]  $x  -  DOMAIN ENUMERATION" | tee -a ${out}
  if [ $option_connect != "0" ] ; then
    error_code=6; f_CURL_WRITEOUT "$x"
    if [ $? = ${error_code} ]; then
      echo -e "${R}$x  WEBSITE CONNECTION: FAILURE${D}\n"
      webpresence="false"; echo -e "\n $x WEBSITE CONNECTION: FAILURE\n" >> ${out}
    else
      webpresence="true"; declare -a curl_array=(); curl_array+=(-sLkv)
      echo -e "WEBSITE CONNECTION:  ${G}SUCCESS${D}\n"
    fi
  else
    webpresence="false"; option_webdomain="n"
  fi
  f_DOMAIN_STATUS "$x" | tee -a ${out}
  [[ -f $temp/ips_all ]]  && cat $temp/ips_all >> $temp/ips.list
  if [ $webpresence = "true" ]; then
    for a in $(f_EXTRACT_IP4 "$temp/ips_all"); do f_HOST_SHORT "$a"; done | tee -a ${out}
    [[ -f $temp/webdom_whois ]] && webdomain=$(grep -sE "^Domain:" $temp/webdom_whois | awk '{print $NF}' | tr -d ' ')
    domain_webhost=$(f_printWEBHOST)
    [[ $webdata = "true" ]] && f_PAGE "$x" | tee -a ${out}
    if [ -n "$webdomain" ]; then
      echo -e -n "\n${B}Option   >  ${C}WEBDOMAIN  ${B}>${D}  Include $webdomain in enumerations ${B}[y] | [n] ?${D}  " ; read -r option_webdomain
      [[ $option_webdomain = "y" ]] && f_URLSCAN_DUMP "$webdomain"
    else
      option_webdomain="n"
    fi
  fi
  #**************  DNS RECORDS **************
  echo '' | tee -a ${out}; target_type="dnsrec"
  f_DOMAIN_DNS "$x" | tee -a ${out}
  [[ $option_webdomain = "y" ]] && f_DOMAIN_DNS "$webdomain" | tee -a ${out}
  for mxa in $(f_EXTRACT_IP4 "$temp/m4"); do echo ''; f_HOST_SHORT "$mxa"; done | tee -a ${out}
  #************** SSL **************
  if [ $option_connect != "0" ]; then
    option_starttls="0"; tls_port="443"; quiet_dump="false"; ssl_diag="false"
    declare ssl_array1; ssl_array1+=(-servername $x -verify_hostname $x)
    f_CERT_INFO "$x" | tee -a ${out}; unset ssl_array1
    declare ssl_array1; ssl_array1+=(-servername $webdomain -verify_hostname $webdomain)
    [[ $option_webdomain = "y" ]] && f_CERT_INFO "$webdomain" | tee -a ${out}
  else
    include_subs="false"; f_CERT_SPOTTER "$x" | tee -a ${out}
  fi
  #**************  ZONE TRANSFER (OPTIONAL) **************
  [[ $option_axfr = "y" ]] && f_AXFR "$x" | tee -a ${out}
  [[ $option_axfr = "y" ]] && [[ $option_webdomain = "y" ]] && f_AXFR "$webdomain" | tee -a ${out}
  #************** Subdomains / ASNs **************
  target_type="subdomain"
  include_subs="true"; f_CERT_SPOTTER "$x" > ${outdir}/DOMAIN_CRT_ISSUANCES.${x}.txt
  [[ $option_webdomain = "y" ]] && f_CERT_SPOTTER "$webdomain" > ${outdir}/WEBDOMAIN_CRT_ISSUANCES.${webdomain}.txt
  f_SUBS_HEADER "$x" | tee -a ${out}; subcount=$(f_countL "$(sort -uV $temp/ips.list)")
  if [ $subdomain_host_details = "true" ] && [[ $subcount -lt 101 ]]; then
    if [ -f $temp/subdomains_$x ]; then
      f_HEADLINE3 "[SUBDOMAINS]  $x" | tee -a ${out}; cat $temp/subdomains_$x | tee -a ${out}
    fi
    if [ -f $temp/subdomains_$webdomain ]; then
      f_HEADLINE3 "[SUBDOMAINS]  $webdomain" | tee -a ${out}; cat $temp/subdomains_$webdomain | tee -a ${out}
    fi
  fi
  #**************  WHOIS DATA  -  NETWORK RANGES & ISPs  **************
  option_detail="1"
  rir=""; echo '' | tee -a ${out}
  f_HEADLINE "RIR WHOIS DATABASE OBJECTS  ($file_date)" > ${outdir}/NETW_WHOIS_OBJECTS-${x}.txt
  echo -e "The following objects are searchable within the INVERSE whois search option [w1]\n" >> ${outdir}/NETW_WHOIS_OBJECTS-${x}.txt
  echo -e "Supported RIRs: AFRINIC, APNIC & RIPE\n" >> ${outdir}/NETW_WHOIS_OBJECTS-${x}.txt
  echo ''; f_Long; echo -e "\nGathering information about network ranges & service provider contacts ...\n"
  # LACNIC DOES NOT USE NETNAMES
  if [ -f $temp/lacnic_nets ]; then
    f_HEADLINE3 "[LACNIC]  NETWORKS" > $temp/domain_nets; echo '' >> $temp/domain_nets
    sed G $temp/lacnic_nets | sed 's/~/-/' >> $temp/domain_nets
    [[ $(wc -l < $temp/lacnic_nets) -gt 5 ]] && echo '' >> $temp/domain_nets
  fi
  # QUERY PREFIXES, NET RANGES & POC BY IP & NETWORK NAME
  for addr in $(cat $temp/net_lookup.list); do
    [[ -f $temp/whois_records ]] && rm $temp/whois_records
    [[ -f $temp/nets ]] && rm $temp/nets; [[ -f $temp/nhandle ]] && rm $temp/nhandle; [[ -f $temp/whois ]] && rm $temp/whois
    rir=""; netname=""; netname_table=""; pfx_addr=""; net_addr=""; query_addr=""; netname_count=""
    f_getRIR "$addr"
    if [ $ignore_hosting = "0" ]; then
      is_hosting="false"
    else
      check_hosting=$($CURL -s -m 10 "http://ip-api.com/json/${addr}?fields=16777216" | $JQ '.hosting')
      [[ $check_hosting = "true" ]] && is_hosting="true" || is_hosting="false"
    fi
    if [ -n "$rir" ] && [ $rir != "lacnic" ]; then
      f_get_RIPESTAT_WHOIS "$addr"
      if [ -z "$check_ianablk" ] && [ -z "$check_cli" ]; then  # check if resource is assigned
        echo '' >> $temp/domain_nets
        pfx_addr=$(grep -w "$addr" $temp/net_table | cut -d '|' -f 2 | tr -d ' ' | head -1)
        netname_table=$(grep -w "$addr" $temp/net_table | cut -d '|' -f 3 | tr -d ' ' | head -1)
        # ARIN
        if [ $rir = "arin" ]; then
          # get most specific nethandle
          nhandle=$($JQ '.data.records[]? | .[] | select (.key=="NetHandle") | .value' $temp/whois.json | sort -uV | tail -1)
          [[ -n "$nhandle" ]] && $TOUT 20 $WHOIS -h whois.arin.net "! $nhandle" > $temp/nhandle
          netname=$(f_VALUE ":" "$(grep -s -m 1 'NetName:' $temp/nhandle)")
          outfile="${outdir}/NET_RANGES.${netname}.txt"
          abuse_mail=$(f_EXTRACT_EMAIL "$(grep -s -m 1 'OrgAbuseEmail:' $temp/nhandle)")
          f_HEADLINE3 "[ARIN]   NET:  $netname"  >> $temp/domain_nets
          echo -e "[@] $abuse_mail\n___\n\n" >> $temp/domain_nets
          cidr=$(f_VALUE ":" "$(grep -s -m 1 'CIDR:' $temp/nhandle)"); cidr_count=$(f_countW "$cidr")
          if [ -n "$cidr" ] && [[ $cidr_count -lt 5 ]]; then
            print_netaddr="$cidr"
          else
            print_netaddr=$(f_VALUE ":" "$(grep -s -m 1 'NetRange:' $temp/nhandle)" | sed 's/^/ /')
          fi
          echo -e "$print_netaddr\n" | tee -a ${outdir}/ARIN_NETS_OVERVIEW_$x.txt >> $temp/domain_nets
          f_VALUE ":" "$(grep -s -m 1 'Organization:' $temp/nhandle)" | sed 's/^/  /' | tee -a ${outdir}/ARIN_NETS_OVERVIEW_$x.txt >> $temp/domain_nets
          cust_id=$($JQ '.data.records[]? | .[] | select (.key=="Customer") | .value' $temp/whois.json | grep -sEo "C+[0-9]{8,10}")
          [[ -n "$cust_id" ]] && customer=$($JQ '.data.records[]? | .[] | select (.key=="Customer") | .value' $temp/whois.json | sed 's/^/  /')
          [[ -n "$customer" ]] && echo -e "$customer" | tee -a ${outdir}/ARIN_NETS_OVERVIEW_$x.txt >> $temp/domain_nets
          f_VALUE ":" "$(grep -s -m 1 'OrgId:' $temp/nhandle)" >> $temp/arin_contacts
          if [ $is_hosting = "false" ]; then
            whois -h whois.ripe.net -- "--no-personal -a $netname" | sed -e '/./{H;$!d;}' -e 'x;/IANA-BLK/d' | sed 's/-GRS//' |
            sed 's/# Filtered//' | grep -saEv "DUMY-RIPE" | sed '/source:/G' | sed -e '/./{H;$!d;}' -e 'x;/ARIN/!d' > $temp/arin_nets
            f_VALUE ":" "$(grep -s -m 1 'OrgId:' $temp/nhandle)" >> $temp/orgs_non_hosting
          fi
          echo '' >> $temp/domain_nets
          echo -e "\n\n$netname (ARIN)  $print_netaddr\n" >> $temp/nets_overview
          f_VALUE ":" "$(grep -s -m 1 'Organization:' $temp/nhandle)" | sed 's/^/  /' >> $temp/nets_overview
          [[ -n "$customer" ]] && echo -e "$customer" >> $temp/nets_overview; echo '' >> $temp/nets_overview
        else
          # RIPE, APNIC, AFRINIC
          net_addr=$($JQ '.data.records[]? | .[] | select (.key=="inetnum") | .value' $temp/whois.json | tr -d ' ')
          netname=$($JQ '.data.records[]? | .[] | select (.key=="netname") | .value' $temp/whois.json)
          outfile="${outdir}/NET_RANGES.${netname}.txt"
          jq -r '.data.records[]? | .[] | select (.key=="admin-c") | .value' $temp/whois.json >> $temp/${rir}_admins
          jq -r '.data.records[]? | .[] | select (.key=="org") | .value' $temp/whois.json >> $temp/${rir}_orgs
          if [ $is_hosting = "false" ]; then
            jq -r '.data.records[]? | .[] | select (.key=="org") | .value' $temp/whois.json >> $temp/orgs_non_hosting
          fi
          f_getWHOIS "$net_addr"
          abuse_mail=$(grep -sEa -m 1 "^% Abuse|^abuse-mailbox:|^e-mail:|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $temp/whois |
          grep -sEo "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b")
          f_getRIR_OBJECTS "$temp/whois" >> ${outdir}/NETW_WHOIS_OBJECTS-${x}.txt
          [[ $netname_table = "NA" ]] && print_netname="$netname" || print_netname="$netname_table"
          f_HEADLINE3 "[$(f_toUPPER "$rir")]   NET:   $netname"  >> $temp/domain_nets
          echo -e "[@] $abuse_mail\n___\n\n" >> $temp/domain_nets
          print_netaddr=$($JQ '.data.records[]? | .[] | select (.key=="inetnum") | .value' $temp/whois.json | sed 's/-/ - /')
          echo -e "  $print_netaddr\n" >> $temp/domain_nets
          isp_admins=$(grep -E "^admin-c:" $temp/whois | head -3 | sort -u | awk '{print $NF}' | sed 's/^/,/' | tr -d ' ' | tr '[:space:]' ' ' |
          sed 's/^\,//' | sed 's/ ,/, /g'; echo ''); net_orgs=$(f_ORG_SHORT "$temp/whois")
          grep -E "^admin-c:" $temp/whois | awk '{print $NF}' | tr -d ' ' | head -2 >> $temp/${rir}_admins
          if [ -n "$net_orgs" ]; then
            grep -sEa -m 1 "^org:|^organisation:" $temp/whois | awk '{print $NF}' | tr -d ' ' >> $temp/${rir}_orgs
            echo -e "  $net_orgs" >> $temp/domain_nets
          else
            descr=$(sed -e '/./{H;$!d;}' -e 'x;/route:/d' $temp/whois | grep -sEa -m 1 "^descr:" | cut -d ':' -f 2- |
            sed 's/^[ \t]*//;s/[ \t]*$//')
            [[ -n "$descr" ]] && echo -e "  $descr" >> $temp/domain_nets
          fi
          sed -e '/./{H;$!d;}' -e 'x;/netname:/!d' $temp/whois | grep -sEoa "^mnt-by:|^country:" > $temp/mnt_cc
          net_ctry=$(f_VALUE ":" "$(grep -sa -m 1 'country:' $temp/whois)")
          mntner=$(f_VALUE ":" "$(grep -sa -m 1 'mnt-by:' $temp/whois)")
          echo -e "\n  Mntner: $mntner | $net_ctry | Admins: $isp_admins\n" >> $temp/domain_nets
          grep -E "^admin-c:" $temp/whois | awk '{print $NF}' | tr -d ' ' | head -2 >> $temp/${rir}_admins
          if [ $is_hosting = "false" ]; then
            $TOUT 15 $WHOIS -h whois.$rir.net -- "--no-personal $netname" > $temp/netname_query
            if [ -f $temp/netname_query ]; then
              [[ $rir = "ripe" ]] && grep -v '^abuse-c:'  $temp/netname_query > $temp/nets || cat $temp/netname_query > $temp/nets
            fi
            echo -e "\n\n$netname ($(f_toUPPER "$rir"))  $print_netaddr\n" >> $temp/nets_overview
            [[ -n "$net_orgs" ]] && echo -e " $net_orgs\n" >> $temp/nets_overview
            echo -e " Mntner: $mntner | $net_ctry | Admins: $isp_admins\n" >> $temp/nets_overview
          fi
        fi # Which RIR?
        # -- ALL PREFIXES WITH SAME NAME USED WITHIN TARGET DOMAIN  (source: pwhois.org) *
        if [ $netname_table != "NA" ]; then
          networks=$(grep -w "$netname_table" $temp/net_table | cut -d '|' -f 2 | sed 's/^[ \t]*//;s/[ \t]*$//' |
          sort -u | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//' | fmt -w 80)
          prefix_count=$(f_countW "$networks")
          echo -e "\n'$netname_table' Prefixes in target domain: $prefix_count\n" >> $temp/domain_nets
           echo -e "$networks\n" | sed 's/^/  /' >> $temp/domain_nets
        fi
        # GET ALL RESOURCES FOR GIVEN NETWORK NAME FROM GIVEN RIR
        if [ $is_hosting = "true" ]; then
          echo -e "\n'$netname' Networks (global): \n\n  HOSTING provider network, skipping search for global network resources" >> $temp/domain_nets
        else
          [[ -f $temp/nets ]] && count_net_instances=$(grep -c 'netname:' $temp/nets) || count_net_instances=0
          if [[ $count_net_instances -gt 1 ]]; then
            f_sortNETS "$netname" >> $temp/domain_nets
          else
            [[ $count_net_instances -eq 0 ]] || echo -e "\n'$netname' Networks (global): 1\n\n  $net_addr" >> $temp/domain_nets
          fi
        fi
      fi # Resource is assigned
    fi # target resource has been identified as being administered by ARIN, RIPE, APNIC or AFRINIC
  done
  #************** Service provider contacts **************
  if [ $isp_contacts = "true" ]; then
    option_detail="2"
    # LACNIC
    if [ -f $temp/poc_lookups ]; then
      for pl in $(cat $temp/poc_lookups); do
        rir="lacnic"; timeout 40 $WHOIS -h whois.lacnic.net $pl > $temp/lacnic_poc
        f_POC "$temp/lacnic_poc" | sed 's/^/ /' | sed 's/^ \*/\*/'
      done > $temp/lacnic_sp; unset rir
     [[ -f $temp/lacnic_sp ]] && f_HEADLINE3 "[LACNIC]  SERVICE PROVIDER ORGANIZATIONS" | tee -a ${out} && cat $temp/lacnic_sp | tee -a ${out}
    fi
    # ARIN
    if [ -f $temp/arin_contacts ]; then
      f_HEADLINE3 "[PROVIDERS]   ORGANIZATIONS  (ARIN)" | tee -a ${out}
      for hdl in $(cat $temp/arin_contacts | sort -u); do
        rir="arin"; timeout 40 $WHOIS -h whois.arin.net -- "o ! $hdl" > $temp/arin_poc
        echo -e "\n\n* $hdl\n"; f_POC "$temp/arin_poc" | sed 's/^/  /'; echo ''
      done | tee -a ${out}; unset hdl; unset rir
    fi
    target_type="org"
    # RIPE ORGs
    if [ -f $temp/ripe_orgs ]; then
      f_HEADLINE3 "[PROVIDERS]  ORGANIZATIONS  (RIPE)" | tee -a ${out}
      for hdl in $(cat $temp/ripe_orgs | sort -u); do
        rir="ripe"; echo -e "\n"; $TOUT 30 $WHOIS -h whois.ripe.net -- "-B $hdl" > $temp/ripe_org_tmp
        sed -e '/./{H;$!d;}' -e 'x;/org-name:/!d' $temp/ripe_org_tmp > $temp/ripe_org
        f_POC "$temp/ripe_org" | sed '/./,$!d' | sed 's/^/  /' | sed 's/  ORG:/\n*/'; echo ''
      done | tee -a ${out}; unset hdl; unset rir
    fi
    # APNIC ORGs
    if [ -f $temp/apnic_orgs ]; then
      f_HEADLINE3 "[APNIC]  SERVICE PROVIDER ORGANIZATIONS" | tee -a ${out}
      for hdl in $(cat $temp/apnic_orgs | sort -u); do
        rir="apnic"; echo -e "\n"; $TOUT 30 $WHOIS -h whois.apnic.net -- "-B $hdl" > $temp/apnic_org_tmp
        sed -e '/./{H;$!d;}' -e 'x;/org-name:/!d' $temp/apnic_org_tmp > $temp/apnic_org
        f_POC "$temp/apnic_org" | sed '/./,$!d' | sed 's/^/  /' | sed 's/  ORG:/\n*/'; echo ''
      done | tee -a ${out}; unset hdl; unset rir
    fi
    # AFRINIC ORGs
    if [ -f $temp/afrinic_orgs ]; then
      f_HEADLINE3 "[AFRINIC]  SERVICE PROVIDER ORGANIZATIONS" | tee -a ${out}
      for hdl in $(cat $temp/afrinic_orgs | sort -u); do
        rir="afrinic"; echo -e "\n"; $TOUT 30 $WHOIS -h whois.afrinic.net -- "-B $hdl" > $temp/afrinic_org_tmp
        sed -e '/./{H;$!d;}' -e 'x;/org-name:/!d' $temp/afrinic_org_tmp > $temp/afrinic_org
        f_POC "$temp/afrinic_org" | sed '/./,$!d' | sed 's/^/  /' | sed 's/  ORG:/\n*/'; echo ''
      done | tee -a ${out}; unset hdl; unset rir
    fi
    # RIPE ADMINS
    if [ -f $temp/ripe_admins ]; then
      f_HEADLINE3 "[RIPE]  ADMIN CONTACTS" | tee -a ${out}
      for hdl in $(cat $temp/ripe_admins | sort -u); do
        rir="ripe"; echo -e "\n\n* $hdl\n"
        $TOUT 30 $WHOIS -h whois.ripe.net -- "-B $hdl" | sed '/role:/{x;p;x;}' | sed '/person:/{x;p;x;}' > $temp/ripe_poc
        f_DOMAIN_POC "$temp/ripe_poc" | sed '/./,$!d' | sed 's/^/  /'; echo ''
      done | tee -a ${out}; unset hdl; unset rir
    fi
    # APNIC ADMINS
    if [ -f $temp/apnic_admins ]; then
      f_HEADLINE3 "[APNIC]  ADMIN CONTACTS" | tee -a ${out}
      for hdl in $(cat $temp/apnic_admins | sort -u); do
        rir="apnic"; echo -e "\n\n* $hdl\n"
        $tout 30 $WHOIS -h whois.apnic.net -- "-B $hdl" | sed '/role:/{x;p;x;}' | sed '/person:/{x;p;x;}' > $temp/apnic_poc
        f_DOMAIN_POC "$temp/apnic_poc" | sed '/./,$!d' | sed 's/^/  /'; echo ''
      done | tee -a ${out}; unset hdl; unset rir
    fi
    if [ -f $temp/afrinic_admins ]; then
      f_HEADLINE3 "[AFRINIC]  ADMIN CONTACTS" | tee -a ${out}
      for hdl in $(cat $temp/afrinic_admins | sort -u); do
        rir="afrinic"; echo -e "\n\n* $hdl\n"
        $tout 30 $WHOIS -h whois.afrinic.net -- "-B $hdl" | sed '/role:/{x;p;x;}' | sed '/person:/{x;p;x;}' > $temp/afrinic_poc
        f_DOMAIN_POC "$temp/afrinic_poc" | sed '/./,$!d' | sed 's/^/  /'; echo ''
      done | tee -a ${out}; unset hdl; unset rir
    fi
  fi  # isp_contacts = true
  #************** Print networks & netranges **************
  f_HEADLINE2 "NETWORKS OVERVIEW\n" | tee -a ${out}
  cat $temp/nets_overview | tee -a ${out}
  f_Long | tee -a ${out}
  echo -e "\n Reminder:  Network names are not considered unique identifiers.\n" | tee -a ${out}
  echo -e " Watch out for false positives within the 'Resources for' sections.\n" | tee -a ${out}
  cat $temp/domain_nets | tee -a ${out}
  if [ -f $temp/orgs_non_hosting ]; then
    for o in $(sort -bifu $temp/orgs_non_hosting); do
      f_netBLOCKS "$o" > $temp/netblock_tmp; netblock_count=$(wc -w < $temp/blockranges)
      if [[ $netblock_count -gt 60 ]]; then
          echo ''; f_HEADLINE3 "[PWHOIS]   $1   NETBLOCKS   -  $file_date"
          echo -e "\nSee output file\n"
      else
        f_netBLOCKS "$o" | tee -a ${outdir}/NET_BLOCKS.${o}.txt
      fi
      [[ -f $temp/netblock_tmp ]] && [[ $report = "true" ]] && cat $temp/netblock_tmp > ${outdir}/NET_BLOCKS.${o}.txt
      [[ -f $temp/netblock_tmp ]] && rm $temp/netblock_tmp
    done
  fi
  #************** pwhois.org org-name search  **************
  domain_org=$(echo "$x" | cut -d '.' -f 1)
  f_HEADLINE3 "[PWHOIS]   ORG-NAME SEARCH:  $domain_org" > ${outdir}/PWHOIS_${domain_org}.txt
  f_PWHOIS_ORG_NAME "$domain_org" >> ${outdir}/PWHOIS_${domain_org}.txt
  #************** Print full list of subdomains **************
  if [ -f $temp/subdomains_$x ]; then
    f_HEADLINE3 "[SUBDOMAINS]  $x" | tee -a ${out}
    if [[ $(wc -l < $temp/subdomains_$x) -lt 601 ]] || [[ $report = "false" ]]; then
      cat $temp/subdomains_$x | tee -a ${out}
    else
      f_HEADLINE2 "$x SUBDOMAINS (IPV4)\n"; echo -e "Output written to ${outdir}/SUBDOMAINS_${x}.txt"
    fi
  else
    [[ -f ${outdir}/Subdomains_HT.${x}.txt ]] && cat ${outdir}/Subdomains_HT.${x}.txt | tee -a ${out}
  fi # -f $temp/subdomains_$x
  if [ -f $temp/subdomains_$webdomain ]; then
    f_HEADLINE3 "[SUBDOMAINS]  $webdomain  SUBDOMAINS" | tee -a ${out}
    if [[ $(wc -l < $temp/subdomains_$webdomain) -lt 601 ]] || [[ $report = "false" ]]; then
      cat $temp/subdomains_$webdomain | tee -a ${out}
    else
      f_HEADLINE3 "$webdomain SUBDOMAINS (IPV4)\n"; echo -e "\nOutput written to ${outdir}/SUBDOMAINS_${webdomain}.txt"
    fi
  else
    [[ -f ${outdir}/Subdomains_HT.${webdomain}.txt ]] && cat ${outdir}/Subdomains_HT.${webdomain}.txt | tee -a ${out}
  fi # -f $temp/subdomains_$webdomain
  if [[ $subcount -gt 0 ]]; then
    if [ $subdomain_host_details = "true" ] && [[ $subcount -lt 80 ]]; then
      target_type="dnsrec"; f_HEADLINE2 "SUBDOMAIN HOSTS ANALYSIS" | tee -a ${out}
      for a in $(f_EXTRACT_IP4 "$temp/subdomain_ips"); do f_Long; f_HOST_SHORT "$a"; echo ''; done | tee -a ${out}
      target_type="subdomain"
    fi
  fi
  if [ $report = "true" ]; then
    f_Long | tee -a ${out}; echo -e "\nSee output directory for additional files, e.g.\n" | tee -a ${out}
    echo -e "RIR whois database objects searchable in option [w1] (inverse whois)" | tee -a ${out}
    echo -e "network address ranges" | tee -a ${out}
    echo -e "announced prefixes for any AS found," | tee -a ${out}
    echo -e "results of pwhois.org org-name search for $domain_org," | tee -a ${out}
   [[ $webdata = "true" ]] && echo -e "HTTP headers and website link dump" | tee -a ${out}
  fi
fi
target_type=""; x=""; echo ''; f_removeDir; f_Menu
;;
#-------------------------------  IP4 REPUTATION, VHOSTS, CVES  -------------------------------
i|ip|ipv4|blocklist|blocklists|blacklists|cve|cves)
f_makeNewDir; unset rir; f_Long; f_optionsTHREAT_INFO; echo -e -n "\n${B}    ?${D}   "  ; read opt1
if [ $opt1 != "0" ]; then
  domain_enum="false"
  if [ $opt1 = "6" ]; then
    [[ $option_connect = "0" ]] && f_targetCONNECT
  else
    option_connect="0"
  fi
  [[ $opt1 = "4" ]] || [[ $opt1 = "6" ]] && target_type="other"
  if [ $opt1 = "6" ]; then
    if [ -n "$is_admin" ]; then
      echo -e "\n\n${B}Options  > ${C}Nmap Target Ports\n"
      echo -e "${B} [1]${D}  Ports found via Shodan (if applicable)"
      echo -e "${B} [2]${D}  Common Services (~ 250 TCP & UDP Ports) & Ports found via Shodan (if applicable)"
      echo -e "${B} [3]${D}  Common Services (~ 250 TCP & UDP Ports), SKIP Shodan API request"
      echo -e "${B} [4]${D}  All TCP ports"
      echo -e "${B} [5]${D}  Customize ports (TCP)"
      echo -e "${B} [6]${D}  Customize ports (TCP/UDP)"; echo -e -n "\n${B}  ? ${D}  " ; read -r option_ports
      if [ $option_ports = "3" ]; then
        ports="${services_tcp},${services_udp1}"
      elif [ $option_ports = "4" ]; then
        ports="-p-"
      elif [ $option_ports = "5" ] || [ $option_ports = "6" ]; then
        echo -e -n "\n${B}Set     > Ports  ${D}- e.g. U:69,T:636,T:989-995  ${B}>>${D} "; read -r ports_input
        ports="-p $(echo $ports_input | tr -d ' ')"
      fi
      echo -e "\n\n${B} Options  > ${C}Nmap Scripts - Aggression Level\n"
      echo -e "${B} [1]${D}  Safe Mode"
      echo -e "${B} [2]${D}  Aggressive"
      echo -e -n "\n${B}  ?${D}   " ; read option_scripts
      if [ $option_scripts = "1" ]; then
        script_choice="$nse1"
      if [ $option_ports = "1" ] || [ $option_ports = "4" ] || [ $option_ports = "5" ]; then
        nmap_array+=(-T4 -sS -sV -O --osscan-limit --version-intensity 7 -Pn -R --resolve-all --open)
      else
        nmap_array+=(-T4 -sS -sU -sV -O --osscan-limit --version-intensity 7 -Pn -R --resolve-all --open)
      fi
      elif [ $option_scripts = "2" ]; then
        script_choice="${nse1},${nse2}" && script_args="--script-args=http-methods.test-all"
        if [ $option_ports = "1" ] || [ $option_ports = "4" ] || [ $option_ports = "5" ]; then
          nmap_array+=(-T4 -sS -sV -O --version-intensity 9 -Pn -R --resolve-all --open)
        else
          nmap_array+=(-T4 -sS -sU -sV -O --version-intensity 9 -Pn -R --resolve-all --open)
        fi
      fi
    else
      f_WARNING
    fi
  else
    f_getTHREAT_FEEDS_IP
    if [ $opt1 != "3" ] || [ $opt1 != "4" ]; then
      threat_enum="true"; include_subs="false"; option_detail="1"
      if [ $opt1 = "2" ]; then
        target_type="domain"; f_getTHREAT_FEEDS_DOMAIN
      fi
      if [ $opt1 = "1" ]; then
        target_type="default"; f_get_IX_PFX; out=${outdir}/THREAT_ENUM.$file_date.txt
        echo -e -n "\n${B}Option   >  ${C}RapidDNS API ${B}>${D} Perform reverse IP / VHosts lookup ${B}[y] | [n] ?${D}  " ; read -r opt2
      fi
    fi
  fi
  echo ''; f_Long
  echo -e -n "\n${B}Target  >  [1]${D}  Set Target  ${B}|  [2]${D}  Read from file  ${B}?${D}  " ; read -r option_target
  f_setTARGET
  if [ $opt1 = "3" ]; then
    target_type="default"; out="${outdir}/BLcheck.IPv4.${file_date}.txt"
    f_HEADLINE "[REPUTATION]   IP BLOCKLIST CHECK  -  $file_date" | tee -a ${out}
  fi
  if [ $opt1 = "4" ]; then
    target_type="domain"; out="${outdir}/BLcheck.DOMAINS.${file_date}.txt"
    f_HEADLINE "[REPUTATION]   IP BLOCKLIST CHECK  -  $file_date" | tee -a ${out}
  fi
  if [ $opt1 = "5" ]; then
    target_type="other"; out="${outdir}/CVE_Check_API.${file_date}.txt"
    f_HEADLINE "[VULNS]   CVE CHECK  (source: shodan.io)  -  $file_date" | tee -a ${out}
  fi
    for x in $(cat $temp/targets.list); do
      f_getTYPE "$x"
      if [ $opt1 = "2" ] || [ $opt1 = "3" ]; then
        if [ -f $temp/targets_name ]; then
          include_subs="false"; out=${outdir}/THREAT_ENUM.$x.txt; lod="2"
          f_HEADLINE3 "[THREAT ENUM]  $x  - $file_date" | tee -a ${out}
          f_DOMAIN_THREAT_ENUM "$x" | tee -a ${out}
        fi
      elif [ $opt1 = "6" ]; then
        if [ -n "$is_admin" ]; then
          filename=$(echo "$x" | tr ':' '_' | tr '/' '_'); out="${outdir}/NMAP_VULN_${file_date}_${x}.txt"
          target_type="domain"
          f_HEADLINE3 "[NMAP]  VULN SCAN  -  $x  -  $file_date" | tee -a ${out}  
          if [ $target_cat = "host4" ] || [ $target_cat = "hostname" ]; then
            opt_v6=''; [[ $target_cat = "hostname" ]] && target_v4=$(f_RESOLVE_v4 "$x") || target_v4="$x"
            for t in $target_v4; do f_HOST_SHORT "$t"; done  | tee -a ${out}
            if [ $option_ports = "1" ] || [ $option_ports = "2" ]; then
              if [ -f $temp/detected_ports ] && [[ $(wc -w < $temp/detected_ports) -gt 0 ]]; then
                [[ $option_ports = "2" ]] && echo "$services_tcp" | sed 's/,/\n/g' | tr -d ' ' >> $temp/detected_ports
                ports_tcp=$(sort -ug $temp/detected_ports | sed 's/^/,T:/' | tr '[:space:]' ' ' | tr -d ' ' | sed 's/^\,//')
                ports="${ports_tcp},${services_udp1}"
              else
                [[ $option_ports = "2" ]] && ports="${services_tcp},${services_udp1}"
              fi
            fi
            [[ -n "$ports" ]] && f_RUN_NMAP "$x" | tee -a ${out}
          elif [ $target_cat = "host6" ]; then
            opt_v6='-6'; f_RUN_NMAP "$x" | tee -a ${out}
          fi
        fi
      else
        if [[ $x =~ $REGEX_IP4 ]]; then
          [[ $opt1 = "1" ]] && f_HOST_DEFAULT "$x" | tee -a ${out}
          [[ $opt1 = "4" ]] && f_BLOCKLIST_CHECK "$x" | tee -a ${out}
          [[ $opt1 = "5" ]] && f_CVES "$x"  | tee -a ${out}
        else
          echo -e "\nTarget type not supported in this option\n"
        fi
      fi
    done
   unset target_type; unset x; unset rir; echo ''; f_Long; f_targetCONNECT
fi
f_removeDir; f_Menu
;;
#-------------------------------  NETWORKS  -------------------------------
n|net|network)
f_makeNewDir; f_Long; unset rir; domain_enum="false"; target_type="net"; unset nmap_array
f_optionsNET ; echo -e -n "\n${B}    ?${D}   " ; read -r netop
if [ $netop != "0" ] ; then
  [[ $netop -lt 11 ]] && option_scope="2" || option_scope="1"
  [[ $option_scope = "1" ]] && option_connect="1" && custom_file="false"
  [[ $netop = "2" ]] || [[ $netop = "12" ]] && psweep="true" || psweep="false"
  if [ $netop = "1" ]; then
    net_report="true"; option_filter="n"; echo -e "\n${B}Options  > ${C}Type\n"
    echo -e "${B} [1]${D} IPv4 Network(s)" ; echo -e "${B} [2]${D} IPv6 Network(s)"
    echo -e -n "\n${B}  ?${D}   "  ; read -r option_type; echo ''; f_Long
  elif [[ $netop -gt 5 ]]; then
    f_printIF_ADDRESSES; f_printROUTES
  fi
  echo -e -n "\n${B}Target  >  [1]${D}  Set Target  ${B}|  [2]${D}  Read from file  ${B}?${D}  " ; read -r option_target
  f_setTARGET
  if [ -f $temp/targets_nets ]; then
    #************** - NETWORK ADDRESS SPACE ENUM - **************
    if [ $netop = "5" ]; then
      target_type="whois_target"
      out="${outdir}/ADDR_SPACE_ENUM.${file_date}.txt"
      echo -e -n "\n${B}Options  >  ${D}Filter results  ${B}[y] | [n]  ?${D}  " ; read option_filter
      if [ $option_filter = "y" ] ; then
        echo -e -n "\n${B}Filter   >  ${D}Single Searchterm or csv - e.g. access,backbone,service  ${B}>>${D}  " ; read -r filter
        echo "$filter" | tr -d ' ' | sed 's/,/\n/g' | tr -d ' ' > $temp/filters
      fi
      echo '' | tee -a ${out}; f_HEADLINE "PREFIX ADDRESS SPACE/SUBNET SEARCH  ($file_date)" | tee -a ${out}
      if [ $option_filter = "y" ] ; then
        echo -e "\nSearching for ...\n" | tee -a ${out}; cat $temp/filters | tee -a ${out}
        echo -e "\nwithin\n" | tee -a ${out}
      else
        echo -e "\nSearching within ...\n" | tee -a ${out}
      fi
      cat $temp/targets_nets | tee -a ${out}; echo '' | tee -a ${out}
      for x in $(cat $temp/targets_nets); do
        rir=""; f_getTYPE "$x"; [[ $bogon = "FALSE" ]] && f_HEADLINE "$x" && f_getRIR "$x"
        if [ -n "$rir" ] && [ $rir != "arin" ] && [ $rir != "lacnic" ]; then
            f_getLESS_SPECIFICS "$x" && f_getMORE_SPECIFICS "$x"; f_CLEANUP_FILES
        fi
      done | tee -a ${out}
    else # netop = ?
      #************** - CUSTOMIZE OUTPUT FILENAME - **************
      if [ $report = "false" ]; then
        option_filename="n"; custom_file="false"
      else
        echo -e -n "\n${B}Option > ${D}Set Custom Name for Output File ${B}[y] | [n]  ?${D}  " ; read option_filename
        if [ $option_filename = "y" ]; then
          custom_file="true"; echo -e -n "\n${B}Output > ${C}OUTPUT - FILE NAME ${B}>>${D}  " ; read filename
          out=${outdir}/$filename.txt
        else
          custom_file="false"
        fi
      fi
      #**************  CONFIG - OPTION 1) **************
      if [ $netop = "1" ]; then
        echo -e "\n${B}Options  > ${C}DETAILS I > Network whois\n"
        echo -e "${B} [1]${D} Network Whois ${bold}Overview${D}"
        echo -e "${B} [2]${D} Network ${bold}Contact Details${D}"
        echo -e "${B} [3]${D} Brief summary only${D}"
        echo -e -n "\n${B}  ? ${D}  " ; read -r net_report1
        [[ $net_report1 = "1" ]] && option_detail="3"; [[ $net_report1 = "2" ]] && option_detail="2";  [[ $net_report1 = "3" ]] && option_detail="0"
        echo -e "\n${B}Options  > ${C}DETAILS II\n"
        echo -e "${B} [1]${D} Subnets, related prefixes & geographic distribution"
        if [ $option_type = "1" ]; then
          echo -e "${B} [2]${D} Ping Sweep (Nmap)  $denied"
          echo -e "${B} [3]${D} BOTH"
        fi
        echo -e "${R} [0]${D} SKIP"; echo -e -n "\n${B}  ? ${D}  " ; read -r net_report2
        if [ $option_type = "1" ]; then
          [[ $net_report2 = "2" ]] || [[ $net_report2 = "3" ]] && psweep="true" || psweep="false"
        else
          psweep="false"
        fi
        if [ $option_type = "2" ]; then
          net_report3="0"; net_report4="0"
          echo -e "\nSkipping the following IPv4 Options:\n"
          echo -e "\nPing Sweep, Net DNS, Service Banners, CVEs"
        else
          echo -e "\n${B}Options  > ${C}DETAILS III - DNS${D}\n"
          echo -e "${B} [1] ${C}NMAP${B}   >${D}  Reverse DNS Lookup"
          echo -e "${B} [2] ${C}API${B}    >${D}  Reverse IP Lookup (hackertarget.com API max. size: /24)"
           echo -e "\n${B} [3]${D} BOTH"; echo -e "${R} [0]${D} SKIP"
          echo -e -n "\n${B}  ? ${D}  " ; read -r net_report3
          [[ $net_report3 = "1" ]] || [[ $net_report3 = "3" ]] && rdnsv6="false"
          echo -e "\n${B}Options  > ${C}DETAILS IV > Service Banners / CPEs & CVEs\n"
          echo -e "${B} [1] ${C}API${B} >${D}  Banners         (hackertarget.com IP API max. size: /16)"
          echo -e "${B} [2] ${C}API${B} >${D}  CPEs & Vulners  (Shodan API)"
          echo -e "\n${B} [3]${D} BOTH"; echo -e "${R} [0]${D} SKIP"; echo -e -n "\n${B}  ? ${D}  " ; read -r net_report4
        fi # IPv4 vs IPv6
      fi # netop = 1 (config)
      #************** - PING SWEEP CONFIG - **************
      if [ $psweep = "true" ]; then
      [[ $option_connect = "0" ]] && f_targetCONNECT
        if [ $option_connect = "0" ]; then
          echo -e "\nPlease enable target-connect mode\n"
        else
            if [ $option_scope = "2" ]; then
              [[ $custom_file = "false" ]] && out="${outdir}/PingSweep_${file_name}.txt"
              echo -e -n "\n${B}Option   >  ${D}Run Nmap with elevated priviliges ${B}[y] | [n]  ?${D}  " ; read option_root
            fi
            if [ $option_scope = "1" ]; then
              if [ -n "$is_admin" ]; then
                option_root="y"
                [[ $custom_file = "false" ]] && out="${outdir}/LAN_PingSweep_${file_name}.txt"
                echo -e "${B} [1]${D} Local Network - ARP ping"
                echo -e "${B} [2]${D} Local Network - alternative probes (disable ARP)"
                echo -e -n "\n${B}  ? ${D}  " ; read psweep_local
                [[ $psweep_local = "2" ]] && option_pingsweep="3" || option_pingsweep="0"
              else
                option_root="n"; f_WARNING_PRIV; option_pingsweep="0"
              fi
            elif [ $option_scope = "2" ]; then
              echo -e "${B} [1]${D} Use Nmap Defaults"; echo -e "${B} [2]${D} Send more probes"
              echo -e "${B} [3]${D} Customize options"; echo -e -n "\n${B}  ? ${D}  " ; read option_pingsweep
            fi
            if [ $option_pingsweep = "3" ]; then
              declare psweep_array
              [[ $option_scope = "1" ]] && [[ $option_root = "y" ]] && psweep_array+=(--disable-arp-ping)
              echo -e "\n${B}Options > ${C}PING${B} > PROTOCOLS${B} > ${C}TCP\n"
              echo -e "${B} [1]${D} TCP SYN"
              echo -e "${B} [2]${D} TCP ACK"
              echo -e "${B} [3]${D} BOTH"
              echo -e "${R} [0]${D} SKIP"
              echo -e -n "\n${B}  ? ${D}  " ; read option_tcp
              if [ $option_tcp = "1" ] || [ $option_tcp = "3" ]; then
                echo -e -n "\n${B}Ports   > ${C} TCP SYN ${B}>  e.g. 25,80,135  ${B}>>${D}  " ; read syn_ports; psweep_array+=(-PS${syn_ports})
              fi
              if [ $option_tcp = "2" ] || [ $option_tcp = "3" ]; then
                echo -e -n "\n${B}Ports   > ${C} TCP ACK ${B}>  e.g. 25,80,135  ${B}>>${D}  " ; read ack_ports; psweep_array+=(-PA${ack_ports})
              fi
              if [ $option_root = "y" ]; then
                echo -e "\n${B}Options > ${C}PING${B} > PROTOCOLS${B} > ${C}ICMP${D}\n"
                echo -e "${B} [1]${D} ICMP ECHO"
                echo -e "${B} [2]${D} ICMP TIMESTAMP"
                echo -e "${B} [3]${D} BOTH"
                echo -e "${R} [0]${D} SKIP"
                echo -e -n "\n${B}  ? ${D}  " ; read option_icmp
                [[ $option_icmp = "1" ]] || [[ $option_icmp = "3" ]] && psweep_array+=(-PE)
                [[ $option_icmp = "2" ]] || [[ $option_icmp = "3" ]] && psweep_array+=(-PP)
                echo -e "\n${B}Options > ${C}PING${B} > PROTOCOLS${B} > ${C}IP PROTOCOL SCAN\n"
                echo -e "${B} [1]${D} IP Protocol Scan (sends multiple ICMP, IGMP & IP-in-IP packets)"
                echo -e "${R} [0]${D} SKIP"; echo -e -n "\n${B}  ? ${D}  " ; read option_PO; [[ $option_PO = "1" ]] && psweep_array+=(-PO)
                echo -e "\n${B}Options > ${C}PING${B} > PROTOCOLS${B} > ${C}UDP & SCTP\n"
                echo -e "${B} [1]${D} SCT (Stream Control Transmission Protocol)"
                echo -e "${B} [2]${D} UDP"
                echo -e "${B} [3]${D} BOTH"
                echo -e "${R} [0]${D} SKIP"
                echo -e -n "\n${B}  ? ${D}  " ; read option_udp
                if [ $option_udp = "2" ] || [ $option_udp = "3" ]; then
                  echo -e -n "\n${B}Ports   > ${C} UDP ${B}>  e.g. 53,123     ${B}>>${D}  " ; read udp_ports; psweep_array+=(-PU${udp_ports})
                fi
                if [ $option_udp = "1" ] || [ $option_udp = "3" ]; then
                  echo -e -n "\n${B}Ports   > ${C} SCT ${B}>  e.g. 25,80,135  ${B}>>${D}  " ; read sct_ports; psweep_array+=(-PY${sct_ports})
                fi
              fi # option_root = true ?
            fi # option_pingsweep = 3
          fi # optio _connect != 0 ?
      fi # ping sweep config
      #************** - BANNERS / CVES - **************
      if [ $netop =  "3" ]; then
        option_scope="2"; psweep="false"; option_detail=0
        echo -e "\n${B}Options  > ${C} Service Banners / CPEs & CVEs  (API)\n"
        echo -e "${B} [1] ${C}hackertarget.com IP tools ${D}   Banners  (max. size: /16)"
        echo -e "${B} [2] ${C}shodan.io Internet DB     ${D}   CPEs, CVEs, hostnames"
        echo -e "${B} [3] ${C} BOTH [1] & [2]"
        echo -e "\n${B} [4]${D} NMAP"; echo -e "${B} [5]${D} NMAP via Proxychains"
        echo -e -n "\n${B}  ? ${D}  " ; read option_banners
        if [ $option_banners = "4" ] || [ $option_banners = "5" ]; then
          if [ $option_connect != "0" ] && [ -n "$is_admin" ]; then
            [[ $option_banners = "5" ]] && proxych="proxychains" || proxych=''
            nmap_array+=(-PE -PP -PS25,80,443 -PA80,443,3389 -PU:53,40125 -sS -sU -sV -O --osscan-limit --version-intensity 5 -T4 -R)
            scripts="--script=$nse1"; ports="-p $top80"; script_args=''
          fi
        fi
      fi
      #**************  LAN NMAP CONFIG **************
      if [ $netop =  "13" ]; then
        if [ -n "$is_admin" ]; then
          option_root="y"; scripts=""; script_args=""; declare -a nmap_array=()
          f_HEADLINE2 "OS, SERVICE & VULNERS SCAN\n"
          echo -e "\n${B}Options  > ${C}Target Ports \n"
          echo -e "${B} [1]${D} Common TCP & UDP Ports (~250, recommended)"
          echo -e "${B} [2]${D} Common TCP & UDP Ports (~250), aggressive Version & OS Scan"
          echo -e "${B} [3]${D} All (TCP) Ports"
          echo -e -n "\n${B}  ?${D}  "; read option_ports
          if [ $option_ports = "1" ]; then
            nmap_array+=(-sS -sU -sV -O --osscan-limit --version-intensity 6 -T4 --system-dns -R --open); ports="-p $top250"
          elif [ $option_ports = "2" ]; then
            nmap_array+=(-sS -sU -sV -O --version-intensity 8 -T4 --system-dns -R --open); ports="-p $top250"
          else
            nmap_array+=(-sS -sV -O --osscan-limit --version-intensity 6 -T4 --system-dns -R --open); ports="-p-"
          fi
          scripts="--script=${nse1},${nse2}"; script_args="--script-args=http-methods.test-all"
        else
          echo -e "\nSorry, this option requires elevated privileges\n"
        fi
      fi # netop = 13
      #************** - NETWORK DNS OPTIONS (IPV4): PUBLIC - **************
      if [ $netop =  "4" ]; then
        psweep="false"; echo ''; f_Long; echo -e "\n   ${B}Options  > ${C}NETWORK rDNS & REVERSE IP (VHOSTS) I\n"
        echo -e "${B} [1] ${C}NMAP${B}   >${D}  Reverse DNS Lookup"
        echo -e "${B} [2] ${C}NMAP${B}   >${D}  Reverse DNS Lookup  (incl. AAAA records for any PTRs found)"
        echo -e "${R} [0]${D} SKIP"
        echo -e -n "\n${B}  ? ${D}  " ; read -r option_net_dns1
        [[ $option_net_dns1 = "2" ]] && rdnsv6="true"  || rdnsv6="false"
        echo -e -n "\n${B}Option   >${C} API >  Reverse IP (Vhosts), max. size /24 ${B}[y] | [n]  ?${D}  " ; read option_netdns2
      fi
      #************** RUN OPTIONS  **************
      [[ $netop = "1" ]] || option_detail="NA"
      for x in $(cat $temp/targets_nets); do
      f_CLEANUP_FILES; f_getTYPE "$x"
      if [ $net_type = "cidr" ]; then
        file_name=$(echo $x | tr ':' '.' | tr '/' '_' | tr -d ' ')
        net_id=$(echo $x | cut -d '/' -f 1 | cut -d '-' -f 1)
        # NETOP 1
        if [ $netop = "1" ]; then
          if [ $bogon = "TRUE" ]; then
            f_NET_HEADER "$x"; echo ''
          else
            [[ $custom_file = "false" ]] && out="${outdir}/NET_Report.${file_date}_${file_name}.txt"
            [[ $option_detail = "0" ]] && f_NET_HEADER "$x" | tee -a ${out} || f_WHOIS_NET "$x" | tee -a ${out}
          fi
        fi
        # IPV4 OPTIONS
        if [ $target_cat = "net4" ]; then
          # PING SWEEP ($netop = 2 || 12)
          if [ $netop = "2" ] || [ $netop = "12" ] ; then
            f_NET_HEADER "$x  PING SWEEP" | tee -a ${out}; f_PING_SWEEP "$x" | tee -a ${out}
          # BANNERS
          elif [ $netop = "3" ]; then
            [[ $option_banners = "1" ]] && [[ $custom_file = "false" ]] && out="${outdir}/BANNERS.${file_date}_${file_name}.txt"
            [[ $option_banners = "2" ]] && [[ $custom_file = "false" ]] && out="${outdir}/CPES+CVES.${file_date}_${file_name}.txt"
            [[ $option_banners = "3" ]] && [[ $custom_file = "false" ]] && out="${outdir}/BANNERS_CVES.${file_date}_${file_name}.txt"
            [[ $option_banners = "4" ]] && [[ $custom_file = "false" ]] && out="${outdir}/NMAP.${file_date}_${file_name}.txt"
            [[ $option_banners = "5" ]] && [[ $custom_file = "false" ]] && out="${outdir}/NMAP_PROXYCH.${file_date}_${file_name}.txt"
            if [ $option_banners = "4" ] || [ $option_banners = "5" ]; then
              f_HEADLINE3 "[NMAP]   $x  -  $file_date" | tee -a ${out}; echo '' | tee -a ${out}
            else
               f_HEADLINE3 "[NET]   $x  BANNERS  -  $file_date" | tee -a ${out}; echo '' | tee -a ${out}
            fi
            [[ $op_banners = "1" ]] || [[ $op_banners = "3" ]] && f_BANNERS "$x" | tee -a ${out}
            [[ $op_banners = "3" ]] && echo '' | tee -a ${out}
            [[ $option_banners = "2" ]] || [[ $option_banners = "3" ]] && f_NET_CVEs "$x" | tee -a ${out}
            [[ $option_banners = "4" ]] || [[ $option_banners = "5" ]] && f_RUN_NMAP "$x" | tee -a ${out}
          # NETWORK DNS
          elif [ $netop = "4" ]; then
            if [ $option_net_dns1 != "0" ]; then
              [[ $custom_file = "false" ]] && out="${outdir}/NET_RDNS.${file_name}.${file_date}.txt"
              f_NET_HEADER "$x" | tee -a ${out}; f_NET_RDNS "$x" | tee -a ${out}
            fi
            if [ $option_netdns2 = "y" ]; then
              [[ $custom_file = "false" ]] && out="${outdir}/REV_IP.${file_name}.${file_date}.txt"
              nh="REVERSE IP  (VHOSTS)"
              f_NET_HEADER "$x" | tee -a ${out}; f_REV_IP "$x" | tee -a ${out}
            fi
          elif [ $netop = "11" ] && [ $addr_type = "private" ]; then
            [[ $custom_file = "false" ]] && out="${outdir}/DUPLICATES.${file_date}_${file_name}.txt"
            f_HEADLINE2 "Checking for duplicates / multihomed hosts ...\n"; echo '' >> ${out}; f_Long >> ${out}
            f_DUPLICATES "$x" | tee -a ${out}
          elif [ $netop = "12" ] && [ $addr_type = "private" ]; then
            [[ $custom_file = "false" ]] && out="${outdir}/PING_SWEEP.${file_date}_${file_name}.txt"
            f_PING_SWEEP "$x" | tee -a ${out} 
          elif [ $netop = "13" ] && [ $addr_type = "private" ]; then
            [[ $custom_file = "false" ]] && out="${outdir}/NMAP.${file_date}_${file_name}.txt"
            f_HEADLINE3 "[NMAP]   $x  -  $file_date" | tee -a ${out}; echo '' | tee -a ${out}
            f_RUN_NMAP "$x" | tee -a ${out}
     
          fi # netop = ?
        fi # target_cat = net4 ?
      fi # net_type = cidr?
      done
    fi # netop != 5 ?
  fi # Target file $temp/nets exists
fi # netop != 0
x=""; target_type=""; f_removeDir; f_Menu
;;
#-------------------------------  SSL -------------------------------
ssl)
f_makeNewDir; f_Long; f_optionsSSL; echo -e -n "\n${B}    ?${D}   "; read op
if [ $op != "0" ]; then
  if [ $option_connect = "0" ] && [ $op != "5" ]; then
    f_WARNING
  else
    domain_enum="false"
    [[ $op = "1" ]] && option_starttls="0"
    [[ $op = "3" ]] && quiet_dump="true" || quiet_dump="false"
    [[ $op = "4" ]] && ssl_diag="true" || ssl_diag="false"
    [[ $op = "5" ]] && target_type="hostname" || target_type="ssl_target"
    if [ $op = "5" ]; then
      echo -e -n "\n${B}Option  >  ${C}Include Subdomains  ${B}[y] | [n] ?${D}  " ; read -r opt_subdomains
      [[ $opt_subdomains  = "y" ]] && include_subs="true" || include_subs="false"
    else
      if [ $op = "2" ] || [ $op = "3" ] || [ $op = "4" ]; then
        echo -e "\n${B}Options  > ${C}STARTTLS\n"
        echo -e "${B} [1]${D}  SMTP"
        echo -e "${B} [2]${D}  IMAP4"
        echo -e "${B} [3]${D}  POP3"
        echo -e "${B} [4]${D}  FTP"
        echo -e "${B} [5]${D}  LDAP"
        if [ $op = "3" ] || [ $op = "4" ]; then
          echo -e "${R} [0]${D}  No STARTTLS"
        fi
        echo -e -n "\n${B}  ?${D}   "  ; read -r option_starttls
      fi
      if [ $option_starttls = "0" ]; then
        echo -e "\n${B}Options  > ${C}Target SSL Port\n"
        echo -e "${B} [1]${D} 443"
        echo -e "${B} [2]${D} Customize port"
        echo -e -n "\n${B}  ? ${D}  " ; read option_sslports
        if [ $option_sslports = "1" ] ; then
          tls_port="443"
        else
          echo -e -n "\n${C}PORT${B} >  ${D}"; read -r input
          tls_port=$(echo $input | sed 's/^ *//' | cut -d ',' -f 1 | cut -d ' ' -f 1)
        fi
      fi
    fi # config: op = ?
    echo -e -n "\n${B}Target  >  [1]${D}  Set Target  ${B}|  [2]${D}  Read from file  ${B}?${D}  " ; read -r option_target
    f_setTARGET
    [[ -f $temp/targets_name ]] && cat $temp/targets_name > $temp/targets_ssl
    [[ -f $temp/targets_ip ]] && cat $temp/targets_ip >> $temp/targets_ssl
    if [ -f $temp/targets_ssl ]; then
      for t in $(cat $temp/targets_ssl); do
        f_CLEANUP_FILES; f_getTYPE "$t"
        if [ $op = "5" ] && [ $target_cat = "hostname" ]; then
          [[ -f $temp/dnsnames ]] && rm $temp/dnsnames
          if [ $include_subs = "true" ]; then
            x=$(f_EXTRACT_HOSTN "$temp/host_domain");
            out="${outdir}/DOMAIN_CERT_ISSUANCES.${x}_${file_date}.txt"
          else
            x="$t"; out="${outdir}/CERTSPOTTER.${x}_${file_date}.txt"
          fi
          lod="1"; f_HEADLINE "$x" | tee -a ${out}; f_HOST_DNS "$x" | tee -a ${out}; f_CERT_SPOTTER "$x" | tee -a ${out}
          if [ $include_subs = "true" ] && [ -f $temp/dnsnames ]; then
            f_HEADLINE2 "Hosts\n" | tee -a ${out}; f_RESOLVE_HOSTS4 "$temp/dnsnames" > $temp/names_res
            sub_ips=$(f_EXTRACT_IP4 "$temp/names_res" | tr '[:space:]' ' ' | fmt -w 60; echo '')
            cat $temp/names_res | tee -a ${out}; f_HEADLINE2 "IP Addresses\n" | tee -a ${out}; echo -e "$sub_ips\n" | tee -a ${out}
          fi
        fi # op = 5
        if [ $op != "5" ] && [ $option_connect != "0" ]; then
          x="$t"
          if [ $quiet_dump = "false" ]; then
            [[ $option_starttls = "0" ]] && out="${outdir}/SSL.${x}.$file_date.txt"
            [[ $option_starttls = "1" ]] && out="${outdir}/SMTP_SSL.${x}_${file_date}.txt"
            [[ $option_starttls = "2" ]] && out="${outdir}/IMAP_SSL.${x}_${file_date}.txt"
            [[ $option_starttls = "3" ]] && out="${outdir}/POP_SSL.${x}_${file_date}.txt"
            [[ $option_starttls = "4" ]] && out="${outdir}/FTP_SSL.${x}_${file_date}.txt"
            [[ $option_starttls = "5" ]] && out="${outdir}/LDAP_SSL.${x}_${file_date}.txt"
          fi
          if [ $target_cat = "hostname" ]; then
            declare ssl_array1; declare ssl_array2
            ssl_array1+=(-servername $x -verify_hostname $x)
            ssl_array2+=(-servername $x)
          fi
            f_CERT_INFO "$x" | tee -a ${out}; unset ssl_array1; unset ssl_array2
        fi # op 1-4
      done
    else
      echo -e "\n${R}Valid target types are Hostnames & IP Addresses\n"
    fi # invalid target(s)
  fi # option_connect = 0 && op != 5
fi
f_removeDir; f_Menu
;;
#-------------------------------  OTHER TOOLS  -------------------------------
t|tools)
f_makeNewDir; f_Long; domain_enum="false"; target_type="other"; f_optionsTOOLS; echo -e -n "\n${B}    ?${D}   " ; read option_tools
if [ $option_tools != "0" ]; then
  [[ $option_tools = "1" ]] && echo -e "${B}\nABUSE CONTACT FINDER > ${C} INPUT:${D}${bold} ASN, IP Addr, Network Addr (CIDR)${D}\n"
  [[ $option_tools = "2" ]] && echo -e "${B}\nRev. Google Analytics Search > ${C} INPUT:${D}${bold} Google analytics ID ${D} e.g. UA-123456\n"
  if [ $option_tools = "6" ]; then
    out="${outdir}DHCP_RS.${file_date}.txt"
    f_NMAP_BCAST "broadcast-dhcp-discover" | tee -a ${out}
    f_DUMP_ROUTER_DHCP_6 | tee -a ${out}
  elif [ $option_tools = "7" ]; then
    out="${outdir}Routing_Protocols.${file_date}.txt"
    f_getDEFAULT_ROUTES | tee -a ${out}
    f_NMAP_BCAST "broadcast-rip-discover" | tee -a ${out}
    f_NMAP_BCAST "broadcast-ospf2-discover" | tee -a ${out}
  elif [ $option_tools = "8" ]; then
    out="${outdir}Interfaces.${file_date}.txt"; f_SYSINFO | tee -a ${out}
  elif [ $option_tools = "9" ]; then
    out="${outdir}PublicIP.${file_date}.txt"; f_PUBIP | tee -a ${out}
  else
    echo -e -n "\n\n${B}Target  >  [1]${D}  Set Target  ${B}|  [2]${D}  Read from file  ${B}?${D}  " ; read -r option_target
    f_setTARGET
    if [ $option_tools = "1" ]; then
      out="${outdir}ABUSE_CONTACTS.${file_date}.txt"; echo '' | tee -a ${out}
      f_HEADLINE2 "ABUSE CONTACT FINDER  ($file_date)\n" | tee -a ${out}
    elif [ $option_tools = "2" ]; then
      out="${outdir}/REV_GOOGLE_ANALYTICS.txt"; echo '' | tee -a ${out}
      f_HEADLINE2 "REVERSE GOOGLE ANALYTICS ($file_date)\n" | tee -a ${out}
    elif [ $option_tools = "3" ]; then
      out="${outdir}/GEOPING_API.${file_date}.txt"; echo '' | tee -a ${out}
    elif [ $option_tools = "4" ]; then
      if [ -n "$is_admin" ]; then
        if [ -f $temp/targets_host4 ] || [ -f $temp/targets_name ]; then
          custom_inf=''; f_Long
          echo -e "INTERFACES\n"; f_printIF_ADDRESSES "up"; echo -e "\nDEFAULT ROUTES"; f_getDEFAULT_ROUTES; echo ''; f_Long
          echo -e -n "\n${B}Set     >${D}  Interface name  (hit enter to use default)  ${B}>>>${D}  "; read -r inf_input
          [[ -n "$inf_input" ]] && inf_input_raw=$(echo "$inf_input" | tr -d ' ') && custom_inf="-e $inf_input_raw"
        fi
      fi
      out="${outdir}/PATH_MTU.${file_date}.txt"; echo '' | tee -a ${out}
    elif [ $option_tools = "5" ]; then
      out="${outdir}/CHECK_DNS.${file_date}.txt"; echo '' | tee -a ${out}
    fi
    for x in $(cat $temp/targets.list); do
      f_CLEANUP_FILES; f_getTYPE "$x"
      if [ $option_tools = "1" ]; then
        if [ $target_cat = "asn" ] || [ $addr_type = "public" ]; then
          f_ABUSEC_FINDER "$x" | tee -a ${out}
        else
          echo -e "\nInput ($x) not supported\n"
        fi
      elif [ $option_tools = "2" ]; then
        ua_id=$(echo "$x" | grep -sEoi "UA-[0-9-]{3,11}")
        if [ -n $ua_id ]; then
          echo -e "\n$ua_id\n" | tee -a ${out}
          $CURL -s -m 20 "https://api.hackertarget.com/analyticslookup/?q=${ua_id}" | tee -a ${out}; echo '' | tee -a ${out}
        fi
      elif [ $option_tools = "3" ]; then
        if [ $target_cat = "host4" ] && [ $addr_type = "public" ]; then
          f_GEO_PING "$x" | tee -a ${out}
        else
          echo -e "\nInput ($x) not supported\n"
        fi
      elif [ $option_tools = "4" ]; then
        if [ $target_cat = "hostname" ] || [ $target_cat = "host4" ]; then
          if [ -n "$is_admin" ]; then
            f_PATH_MTU "$x" | tee -a ${out}
          else
            declare trace_array; trace_array+=(-n); [[ $target_cat = "host4" ]] && trace_array+=(-4)
            f_PATH_MTU_ALT "$x" | tee -a ${out}; unset trace_array
          fi
        elif [ $target_cat = "host6" ]; then
          declare trace_array; trace_array+=(-n); trace_array+=(-6)
          f_PATH_MTU_ALT "$x" | tee -a ${out}; unset trace_array
        fi
      elif [ $option_tools = "5" ]; then
        if [ $host_type = "hostname" ] || [ $host_type = "ip" ]; then
          f_DNS_DIAG "$x"
        else
          echo -e "\nInput ($x) not supported\n"
        fi
      fi
    done
  fi # option_tools = 1 - 5
fi
x=""; target_type=""; f_removeDir; f_Menu
;;
#-------------------------------  TRACEROUTING  -------------------------------
tr|trace|tracert|traceroute|mtr)
f_makeNewDir; f_Long; [[ $option_connect = "0" ]] && f_targetCONNECT && f_Long
if [ $option_connect != "0" ]; then
  f_optionsTRACE;  echo -e -n "\n${B}    ?${D}   "  ; read op
  if [ $op != "0" ]; then
    if [ $op = "2" ] || [ -n "$is_admin" ]; then
      target_type="hop"; domain_enum="false"
      if [ $op = "3" ]; then
        hop_details="0"; echo -e "${B}\nDUBLIN TRACEROUTE  -  ${C} Expected input:${D}${bold} IP or hostname (IPv4 only) ${D}\n"
      elif [ $op = "4" ]; then
        echo -e "${B}\nNMAP FIREWALK  ${C} Expected input:${D}${bold} IP or hostname ${D}\n"
        f_setTARGET
        echo -e "\n\n${B}Option  >  ${C}Max. num of ports${B} to probe per protocol (default: 10)\n"
        echo -e -n "\n${B}Set     >  Num of ports  ${D} ${B}>>${D}  " && read probes_input
        probes=$(grep -sEo -m 1 "[0-9]{1,5}" <<< $probes_input); [[ -n "$probes" ]] && fw_args="--script-args=firewalk.max-probed-ports=$probes"
      elif [ $op = "1" ] || [ $op = "2" ]; then
        declare trace_array; echo -e "${B}\nTRACEROUTING  -  ${C} Expected input:${D}${bold} IP or hostname ${D}\n"
        [[ $op = "1" ]] && option_ip="Auto (default)" || option_ip="Both"
        echo -e -n "\n${B}Options  > ${C} IP Mode ${B} >  [1]${D}  IPv4  ${B}| [2]${D}  IPv6  ${B}| [3]${D}  $option_ip  ${B}?${D}  " ; read IPvChoice
        echo ''
        [[ $IPvChoice = "3" ]] && trace_mode="IP MODE: AUTO"; [[ $IPvChoice = "1" ]] && trace_mode="IP MODE: IPV4" && trace_array+=(-4)
        [[ $IPvChoice = "2" ]] && trace_mode="IP MODE: IPV6" && trace_array+=(-6)
      fi
      # Set target
      echo -e -n "\n${B}Target  >  [1]${D}  Set Target  ${B}|  [2]${D}  Read from file  ${B}?${D}  " ; read -r option_target
      f_setTARGET
      # Set interface
      if [ $op = "1" ] || [ $op = "4" ]; then 
        echo -e -n "\n${B}Set     > ${C}  Interface; hit enter to use default   ${B}>>${D}  " ; read if_input
        if_count=$(f_countW "$if_input")
        if [ $if_count -eq 1 ]; then
          print_if="NIC: $if_input"
          [[ $op = "1" ]] && trace_array+=(--interface $if_input); [[ $op = "4" ]] && custom_inf="-e $if_input"
        fi
      fi
      # General tracerouting options
      if [ $op = "1" ] || [ $op = "2" ]; then
        echo -e -n "\n${B}Set      >${C}  Set max. hops  (default 30)  ${B}>>${D}  " ; read hops
        [[ -n "$hops" ]] && trace_array+=(-m ${hops}); [[ $op = "1" ]] && trace_array+=(-z -n)
        echo -e "\n\n${B}Option   > ${C} Hop Details: ${B} Geolocation-, BGP- & RPKI Data\n"
        echo -e "${B} [1]${D} Show details for each hop"
        echo -e "${R} [0]${D} SKIP"
        echo -e -n "\n${B}  ? ${D}  " ; read hop_details
        if [ $hop_details = "1" ]; then
          hoplist=""; option_detail="1"; f_get_IX_PFX; [[ $op = "2" ]] && trace_array+=(-n)
        else
          [[ $op = "2" ]] && trace_array+=(-b)
        fi
      fi  # Tracerouting options
      if [ $op = "1" ]; then  # MTR options
        echo -e -n "\n${B}Set      >${C}  Ping count ${D} - e.g. 5   ${B}>>${D}  " ; read pingcount
        trace_array+=(-c ${pingcount}); echo -e "\n${B}Options  >${C}  Protocols\n"
        echo -e "${B} [1]${D} ICMP (Type: Echo)"; echo -e "${B} [2]${D} TCP"; echo -e "${B} [3]${D} UDP"
        echo -e "${B} [4]${D} SCTP (Stream Control Transmission Protocol)"; echo -e -n "\n${B}  ? ${D}  " ; read proto
        if [ $proto != "1" ]; then
          if [ $proto = "3" ]; then
            echo -e -n "\n${B}Option UDP  >${C} Target Port (excl. 53)  ${B}>>${D}  " ; read tport_input
          else
            echo -e -n "\n${B}Option   >${C}  Target Port (e.g. 25)  ${B}>>${D}  " ; read tport_input
          fi
          [[ -n "$tport_input " ]] && tport=$(grep -sEo "[0-9]{1,5}"  <<< $tport_input)
        fi
        [[ $proto = "1" ]] && mtr_proto="ICMP"
        [[ $proto = "2" ]] && trace_array+=(--tcp -P $tport) && mtr_proto="TCP:$tport"
        [[ $proto = "3" ]] && trace_array+=(--udp -P $tport) && mtr_proto="UDP:$tport"
        [[ $proto = "4" ]] && trace_array+=(--sct -P $tport) && mtr_proto="SCTP:$tport"
      fi  # MTR options
      if [ -f $temp/targets_trace ]; then
        for x in $(cat $temp/targets_trace); do
          f_CLEANUP_FILES; f_getTYPE "$x"
          [[ $target_cat = "hostname" ]] && file_name="$x" || file_name=$(echo $x | tr ':' '.' | tr '/' '_')
          # Run options
          if [ $op = "4" ]; then
            hop_details="0"; out="${outdir}/FIREWALK_${file_name}_${file_date}.txt" && f_NMAP_FWALK "$x" | tee -a ${out}
          elif [ $op = "3" ] && [ $target_cat != "host6" ]; then
            out="${outdir}/DUBLIN_TRACERT.${file_date}.${file_name}.txt"
            tr_head="DUBLIN TRACEROUTE"; f_TRACE_HEADER "$x" | tee -a ${out}
            ${run_as_sudo} $DUBLINTR -n 15 $a > $temp/dt
            sed -n '/Traceroute from/,/Saved JSON/p' $temp/dt | sed '/==/{x;p;x;G}' | sed 's/NAT ID:/\n     NAT ID:/g' |
            sed '/flow hash/G' | sed '/*/G' | sed "/Saved JSON file/{x;p;x;G}" | tee -a ${out}; f_Long | tee -a ${out}
            sed -n '/Flow ID/,$p' $temp/dt | grep -sEo "Flow ID [0-9]{1,7}|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" |
            sed '/Flow ID/a nnn' | tr '[:space:]' ' ' | sed 's/Flow ID/\n\nFlow ID/g' | sed 's/nnn/\n\n/g' | sed 's/ /  /g' |
            sed 's/^ *//' | fmt -s -w 70 | tee -a ${out}; echo '' | tee -a ${out}
          elif [ $op = "1" ]; then
            [[ $hop_details = "1" ]] && out="${outdir}/MTR_DETAILS.${file_date}_${file_name}.txt" || out="${outdir}/MTR.${file_date}_${file_name}.txt"
            tr_head="$x MTR  ($trace_mode, $mtr_proto, PING COUNT: $pingcount) $print_if"; f_MTR "$x" | tee -a ${out}
          elif [ $op = "2" ]; then
            [[ $hop_details = "1" ]] && out="${outdir}/MTR_DETAILS.${file_date}_${file_name}.txt" || out="${outdir}/TPATH.${file_date}_${file_name}.txt"
            tr_head="TRACEPATH ($trace_mode)"; f_TRACEPATH "$x" | tee -a ${out}
          fi
          # Hop details (ASN, Geolocation, BGP status, bogon-, tor- & IX detection)
          if [ $hop_details = "1" ]; then
            if [ $op = "1" ]; then
              hoplist=$(grep -v 'Wrst' $temp/mtr.txt | grep -sEoi "$REGEX_IP46")
            else
              hoplist=$(grep -E "[0-9]{1,2}:" $temp/trace | sed '/no reply/d' | awk '{print $2}') 
            fi
            # Inspect hops
            for hop in $hoplist; do
              hop_count=""; rtt=""; rir=""
              if [ $op = "1" ]; then
                hop_count=$(sed 's/^ *//' $temp/mtr.txt | grep -E "^[0-9]{1,2}\." | grep -w $hop | cut -s -d '.' -f 1 |
                tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//')
                rtt=$(sed 's/AS???/AS-/' $temp/mtr.txt | grep 'AS' | sed '/???/d' | sed '/^$/d' | grep -w $hop | awk -F'%' '{print $NF}' |
                awk '{print $2}' | tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//')
              else
                hop_count=$(grep "$hop" $temp/trace | grep -E -o "^[0-9]{1,2}:" | tr -d ':' | tr '[:space:]' ' ' |
                sed 's/^[ \t]*//;s/[ \t]*$//')
                rtt=$(grep "$hop" $temp/trace | awk -F'ms' '{print $1}' | awk '{print $NF}' | tr '[:space:]' ' ' |
                sed 's/^[ \t]*//;s/[ \t]*$//')
              fi
              f_HOP "$hop"; echo ''; f_CLEANUP_FILES; rir=""
            done | tee -a ${out}
            if [ -f $temp/hops_public ]; then
              echo '' | tee -a ${out}; f_HEADLINE2 "HOP ADDRESSES (PUBLIC)\n\n" | tee -a ${out}
              cat $temp/hops_public |  tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/ /  /g' | fmt -s -w 60 |
              sed G | tee -a ${out}; rm $temp/hops_public
            fi
            if [ -f $temp/hops_bogon ]; then
              echo '' | tee -a ${out}; f_HEADLINE2 "HOP ADDRESSES (BOGONS)\n\n" | tee -a ${out}
              cat $temp/hops_bogon |  tr '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/ /  /g' | fmt -s -w 60 |
              sed G | tee -a ${out}; rm $temp/hops_bogon
            fi
          fi # Hop details
        done
      else
        echo -e "\n${R}Invalid target type\n${D}\n"
      fi   # ! -f $temp/targets_trace
    else
      f_WARNING_PRIV
    fi # insufficient permissions
  else
    echo ''
  fi # op != 0
else
 f_WARNING
fi
x=""; target_type=""; f_removeDir; f_Menu
;;
#-------------------------------  WHOIS OPTIONS  -------------------------------
w) echo '' ; f_Long; f_optionsWHOIS ;;
w1)
f_makeNewDir; f_Long; option_detail="1"; domain_enum="false"; orgs=''; orgs_other=''
echo -e "\n${B}Options  > Sources > whois Servers >\n"
echo -e "${B} [1]${D}  RIPE"
echo -e "${B} [2]${D}  AFRINIC"
echo -e "${B} [3]${D}  APNIC"
echo -e "${B} [4]${D}  ARIN"
echo -e "\n${B} [0]${D}  Back to the Global Options ${C}Menu${D}"
echo -e -n "\n${B}   ?${D}  " ; read reg_choice
if [ $reg_choice != "0" ]; then
  if [ $reg_choice = "1" ] ; then
    rir="ripe"; iregistry="RIPE" ; rir_server="whois.ripe.net"
  elif [ $reg_choice = "2" ] ; then
    rir="afrinic"; iregistry="AFRINIC" ; rir_server="whois.afrinic.net"
  elif [ $reg_choice = "3" ]; then
    rir="apnic"; iregistry="APNIC" ; rir_server="whois.apnic.net"
  elif [ $reg_choice = "4" ]; then
    rir="arin"; iregistry="ARIN" ; rir_server="whois.arin.net"
  fi
  if [ $rir = "arin" ]; then
    target_type="arin_iwhois"
    f_Long ; echo -e "\n${B}Expected Input${D} - ${C}Org- or Customer ID${D}\n"
    echo -e -n "\n${C}Target  ${B}> [1]${D} Single entry ${B}| [2]${D} Read from file  ${B}?${D}  " ; read -r option_target
    f_setTARGET
    for x in $(cat $temp/targets_other); do
      out=${outdir}/ARIN_IWHOIS_${x}.txt; is_customer=$(grep -sEo "C+[0-9]{8,10}" <<<$x)
      if [ -n "$is_customer" ]; then
        arin_poc=$(f_ARIN_CUST "$x")
      else
        $TOUT 30 $WHOIS -h whois.arin.net "o $x" > $temp/arin_org && arin_poc=$(f_POC "$temp/arin_org")
      fi
      [[ -n "$arin_poc" ]] && f_HEADLINE3 "[ARIN]  $x  ORGANIZATION" | tee -a ${out} && echo "$arin_poc" | tee -a ${out}   
      $TOUT 30 $WHOIS -h whois.arin.net "n - $x" | grep '(' > $temp/arin_tmp
      if [ -f $temp/arin_tmp ]; then
        grep -E "$IP4_ALT" $temp/arin_tmp > $temp/arin4_tmp
        grep -E "$REGEX_IP6" $temp/arin_tmp > $temp/arin6_tmp
        [[ -f $temp/arin4_tmp ]] && netcount4=$(grep -c '(' $temp/arin4_tmp) || netcount4=0
        [[ -f $temp/arin6_tmp ]] && netcount6=$(grep -c '(' $temp/arin6_tmp) || netcount6=0
        if [[ $netcount4 -gt 0 ]] || [[ $netcount6 -gt 0 ]]; then
          f_HEADLINE3 "[ARIN]  $x  NETWORKS" | tee -a ${out}
          echo -e "\nIPv4: $netcount4;  IPv6: $netcount6\n\n" | tee -a ${out}
          if [[ $netcount4 -gt 0 ]]; then
            cut -d ')' -f 2- $temp/arin4_tmp | sed 's/^[ \t]*//;s/[ \t]*$//' > $temp/netlist_tmp; cat $temp/arin4_tmp | tee -a ${out}
            echo '' | tee -a ${out}; f_DEAGGREGATE | tee -a ${out}
          fi
          if [[ $netcount6 -gt 0 ]]; then
            [[ $netcount4 -gt 0 ]] && f_Long | tee -a ${out}
            sed 's/)/)\n\n/' $temp/arin6_tmp | sed '/)/{x;p;x;}' | sed '/:/G' | tee -a ${out}
          fi
        fi
      fi
    done
  else
    target_type="iwhois_target"
    f_Long ; echo -e "\n${B}Expected Input${D} - ${C}ObjectType;SearchTerm${D}  -  e.g.  admin-c;JohnDoeXY-RIPE\n"
    echo -e -n "\n${C}Target  ${B}> [1]${D} Single entry ${B}| [2]${D} Read from file  ${B}?${D}  " ; read option_target
    if [ $option_target = "2" ] ; then
      echo -e -n "\n${B}Target  > ${C}PATH TO FILE ${D}e.g. ./objects.list  ${B}>>${D}   " ; read input
      cat $input > $temp/targets_tmp
    else
      echo -e -n "\n${B}Target  > ${C}SEARCH TERM  ${B}>>${D} " ; read input
      echo "$input" > $temp/targets_tmp
    fi
    grep -sEoi "$PATTERN_IWHOIS" $temp/targets_tmp > $temp/targets
    if [ $option_target = "2" ] && [ $report = "true" ] ; then
      echo -e -n "\n${B}Output  > ${C}OUTPUT - FILE NAME  ${B}>>${D}  " ; read filename
    fi
    headl="$temp/headline"; echo -e "\n"
    echo -e "\n" > ${headl}; f_Long | tee -a ${headl}; echo -e "[$iregistry]  OBJECT & INVERSE SEARCHES  -  $file_date)" | tee -a ${headl}
    f_Long | tee -a ${headl}; echo -e "\nSearching...\n" | tee -a ${headl}; cat $temp/targets | tee -a ${headl}
    echo '' | tee -a ${headl}
    for t in $(cat $temp/targets); do
      x=$(echo $t | grep -E ".*.;.*")
      query_type=$(echo "$x" | cut -d ';' -f 1) ; obj=$(echo "$x" | cut -d ';' -f 2)
      if [ $option_target = "1" ] ; then
        filename=$(echo $x | cut -d ';' -f 2- | tr -d ' ')
      fi
      if [ $query_type = "org" ] ; then
        echo "$obj" | tr -d ' ' >> $temp/orgs.list
      elif [ $query_type = "admin-c" ] ; then
        echo "$obj" | tr -d ' ' | tee -a $temp/objects.list >> $temp/admins1_raw
      elif [ $query_type = "tech-c" ] ; then
        echo "$obj" | tr -d ' ' | tee -a $temp/objects.list >> $temp/admins1_raw
      elif [ $query_type = "abuse-c" ] ; then
        echo "$obj" | tr -d ' ' | tee -a $temp/objects.list >> $temp/admins1_raw
      elif [ $query_type = "mnt-by" ] ; then
        echo "$obj" | tr -d ' ' | tee -a $temp/objects.list >> $temp/mntners
      elif [ $query_type = "mnt-lower" ] ; then
       echo "$obj" | tr -d ' ' | tee -a $temp/objects.list >> $temp/mntners
      elif [ $query_type = "origin" ] ; then
        echo "$obj" | tr -d ' ' | tee -a $temp/objects.list >> $temp/asns.list
      else
        echo "$obj" >> $temp/objects.list
      fi
      $TOUT 10 $WHOIS -h ${rir_server} -- "--no-personal -i ${query_type} ${obj}" >> $temp/whois_temp
      f_whoisFORMAT "$temp/whois_temp" >> $temp/who1
      $TOUT 10 $WHOIS -h ${rir_server} -- "--no-personal ${obj}" >> $temp/whois_temp2
      f_whoisFORMAT "$temp/whois_temp2" >> $temp/who2
    done
    [[ -f $temp/who1 ]] && cat $temp/who1 > $temp/full_output; [[ -f $temp/who2 ]] && cat $temp/who2 >> $temp/full_output
    netcount=$(grep -sEc "^netname:" $temp/whois_temp); netcount4=$(grep -sEc "^inetnum:" $temp/whois_temp)
    netcount6=$(grep -sEc "^inet6num:" $temp/whois_temp)
    [[ -f $temp/admins1_raw ]] && cat $temp/admins1_raw | sort -u > $temp/admins1
    grep -E "^abuse-c:|^admin-c:|^tech-c:" $temp/full_output | awk '{print $NF}' | sort -u > $temp/admins2
    [[ -f $temp/admins1 ]] && diff --suppress-common-lines --ignore-all-space $temp/admins1 $temp/admins2 |
    grep '>' | cut -d ' ' -f 2 | sed 's/^ *//' > $temp/admins_other
    grep -E "^org:" $temp/full_output | awk '{print $NF}' > $temp/orgs.list
    grep -E "^aut-num:|^origin:" $temp/full_output | awk '{print $NF}' | sed 's/AS//g' >> $temp/asns.list
    asns=$(cat $temp/asns.list | sort -ug)
    #**** NETWORKS ****
    if [[ $netcount -gt 0 ]]; then
      sed -e '/./{H;$!d;}' -e 'x;/netname:/!d' $temp/whois_temp |
      grep -sEa -A 1 "^inet(6)?num:|^netname:|^country:|^org:|^abuse-c:|^admin-c:|^tech-c:|^status:|^mnt-by:|^mnt-irt:|^source:" |
      grep -sEav "RIPE-NCC-HM-MNT|RIPE-NCC-LEGACY-MNT|RIPE-NCC-END-MNT|^created:|^remarks:" | sed '/source:/G' | grep -v 'source:' |
      sed '/--/d' | sed '/inetnum:/i ==' | sed '/inet6num:/i ==' | sed '/netname:/i <' | sed '/country:/i |' | sed '/org:/i |' |
      sed '/descr:/i |' | sed '/admin-c:/i |' | sed '/tech-c:/i | TECH~' | sed '/abuse-c:/i | ABUSE~' | sed '/notify:/i |' |
      sed '/upd-to:/i |' | sed '/mnt-irt:/i | MNT-IRT~' | sed '/mnt-by:/i |' | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' |
      tr '[:space:]' ' ' | sed 's/== /\n\n/g' | sed 's/~/:/g' | sort -u > $temp/inets46
      f_HEADLINE3 "[INV.WHOIS]   NETWORKS" | tee -a ${out}
      f_PRINT_NETS "$temp/inets46" | tee -a ${out}
    fi
    target_type="other"
    if [ -n "$asns" ]; then
      f_HEADLINE3 "[$iregistry]   AUTONOMOUS SYSTEMS" | tee -a ${out}
      for a in $asns; do f_AS_SHORT "${a}"; echo ''; done | tee -a ${out}
    fi
    if [ -f $temp/orgs.list ]; then
      f_HEADLINE3 "[$iregistry]   ORGANISATIONS" | tee -a ${out}
      for oid in $(sort -u $temp/orgs.list); do
        timeout 10 $WHOIS -h ${rir_server} -- "--no-personal $oid" > $temp/whois_org
        echo ''; f_ORG_SHORT "$temp/whois_org"; f_getRIR_OBJECTS "$temp/whois_org"
      done | tee -a ${out}
      for oid in $(sort -u $temp/orgs.list); do
        echo '' ; f_netBLOCKS "${oid}"
      done | tee -a ${out}
    fi
    #**** ABUSE CONTACTS / POCs ****
    echo '' | tee -a ${out}; f_HEADLINE3 "[$iregistry]   POINTS OF CONTACT" | tee -a ${out}
    abuse_mb=$(grep -sEoa "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $temp/full_output | sort -u)
    [[ -n "$abuse_mb" ]] && echo -e "\nABUSE MAIL\n\n$abuse_mb\n" | tee -a ${out}
    if [ -f $temp/admins1 ]; then
      [[ -n "$abuse_mb" ]] && f_Long | tee -a ${out}; echo -e "CONTACTS (QUERY)" | tee -a ${out}
      for ac in $(cat $temp/admins1 | sort -u); do echo -e "\n\n$ac\n\n"; f_ADMIN_C "$ac"; echo ''; done | tee -a ${out}
    fi
    if [ -f $temp/admins_other ] && [ $(wc -w < $temp/admins_other) -gt 0 ]; then
      echo '' | tee -a ${out}; f_Long | tee -a ${out}; echo -e "CONTACTS (OTHER)" | tee -a ${out}
      for aco in $(sort -u $temp/admins_other | sort -u); do echo -e "\n\n$aco\n\n"; f_ADMIN_C "$aco"; echo ''; done | tee -a ${out}
    fi
    cat $headl >> ${outdir}/WHOIS.${filename}.txt ; cat ${out} >> ${outdir}/WHOIS.${filename}.txt
  fi # rir != arin
fi # $reg_choice != "0"
echo ''; unset target_type; unset x; f_Menu
;;
w2)
#**************  POC SEARCHES  *******************
f_makeNewDir; f_Long; target_type="whois_target"; domain_enum="false"; unset rir
echo -e "${B}\nWHOIS POC SEARCH > ${C} Expected input:${D}\n"
echo -e "${bold}Org-IDs, NIC-HDLs, name servers, person-/role-/org names${D}\n"
echo -e "Use option ${C}x)${D} to search for network names\n"; f_Long
echo -e "\n${B}Options  > Sources > RIR whois Servers >\n"
echo -e "${B} [1]${D}  RIPE"; echo -e "${B} [2]${D}  AFRINIC"; echo -e "${B} [3]${D}  APNIC"; echo -e "${B} [4]${D}  ARIN"
echo -e -n "\n${B}   ?${D}  "; read option_rir
[[ $option_rir = "1" ]] && rir="ripe"; [[ $option_rir = "2" ]] && rir="afrinic"; [[ $option_rir = "3" ]] && rir="apnic"
 [[ $option_rir = "4" ]] && rir="arin"
if [ -n "$rir" ]; then
  echo -e -n "\n${B}Target  >  [1]${D}  Set Target  ${B}|  [2]${D}  Read from file  ${B}?${D}  " ; read -r option_target
  f_setTARGET
  echo -e "\n${B}Options  > ${C}PoC Details\n\n${R}(CAUTION: Excessive queries for personal details may result in blocked access to RIR databases)\n"
  echo -e "${B} [1]${D} Limit results for personal data"
  echo -e "${B} [2]${D} Look up Full Contact Details (not recommended if searching for names rather than handles)"
  echo -e -n "\n${B}   ?${D}  " ; read option_poc
  if [ $report = "true" ]; then
    echo -e "\n${B}Options  > ${C}Output File\n"
    echo -e "${B} [1]${D} Set custom  name for output file"
    echo -e "${B} [2]${D} Use default (target_input.current_date.txt)"
    echo -e -n "\n${B}   ?${D}  " ; read option_filename
    if [ $option_filename = "1" ]; then
      echo -e -n "\n${B}Output  > ${C}OUTPUT - FILE NAME  ${B}>>${D}  " ; read filename
      out="${outdir}/filename.txt"
    fi
  fi
  if [ -f  $temp/targets_other ]; then
    for x in $(cat $temp/targets.list); do
      if [ $rir = "arin" ]; then
        option_detail="2"; is_customer=$(grep -sEo "C+[0-9]{8,10}" <<<$x)
        if [ -n "$is_customer" ]; then
          arin_poc=$(f_ARIN_CUST "$x")
        else
          $TOUT 30 $WHOIS -h whois.arin.net "e + $x" > $temp/arin_org
          if [[ $(grep -sc "Company:" $temp/arin_org) -gt 0 ]]; then
            arin_poc=$(grep -E "^Name:|^Handle:|^Company:|^Address:|^City:|^StateProv:|^PostalCode:|^Country:|^RegDate:|^Phone:|^Email:" $temp/arin_org |
            sed '/Name:/i ==' | sed '/Handle:/i (' | sed '/Handle:/a )nnn' | sed '/Company:/a nnn' | sed '/^City:/i,' | sed '/^City:/a __' |
            sed '/RegDate:/i nnn RegDate~' | sed '/RegDate:/a |' | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:space:]' ' ' |
            sed 's/== /\n\n/g' | sed 's/nnn/\n\n/g' | sed 's/__//' | sed 's/ ,/,/' | sed 's/( / (/' | sed 's/ )/)/' | sed 's/~/:/'; echo '')
          else
            arin_poc=$(f_POC "$temp/arin_org")
          fi
        fi
        if [ -n "$arin_poc" ]; then
          f_HEADLINE3 "[ARIN]  Poc:  $x" | tee -a ${out} && echo "$arin_poc" | tee -a ${out}    
           arin_mail=$(grep -E -m 1 "AbuseEmail:|^Email:" $temp/arin_org)
           [[ $option_poc = "2" ]] && mail_domain=$(f_EXTRACT_EMAIL "$arin_mail" | cut -d '@' -f 2) || mail_domain=''
          if [ -n "$mail_domain" ]; then
            $TOUT 20 $WHOIS -h whois.arin.net "p $mail_domain" > $temp/poc_additional
            poc_add=$(grep -s '(' $temp/poc_additional)
            if [ -n "$poc_add" ]; then
              f_Medium | tee -a ${out}; echo -e "\nADDITIONAL CONTACTS\n" | tee -a ${out}
              echo "$poc_add" | sort -u -t ')' -k 2 $temp/poc_additional | sort -t '(' -k 1 | sed 's/(/\n\n (/' | sed '/(/G' |
              sed '/)/G' | sed 's/+/ +/' | tee -a ${out}
            fi
          fi
        fi
    else
      timeout 10 $WHOIS -h whois.$rir.net -- "-F -r ${x}"  | tr -d '*' | sed 's/^ *//' | sed '/RIPE-NCC-LEGACY-MNT/d' |
      sed '/RIPE-NCC-HM-MNT/d' > $temp/whois_temp
      found=$(grep -sE "^ro:|^pn:|^mt:|^nh:|^oa:|^on:" $temp/whois_temp | grep "$x" | cut -d ':' -f 1)
      if [ -n "$found" ]; then
        if [ $option_poc = "1" ]; then
          f_HEADLINE2 "POINTS OF CONTACT (QUERY)\n"
          grep -sEa "^oa:|^on:|^an:|^aa:|^cy:|^ro:|^pn:|^it:|^mt:|^de:|^ad:|^ph:|^am:|^em:|^nh:|^ac:|^og:|^mb:" $temp/whois_temp |
          sed 's/^ac:/admin~/' | sed 's/^oa:/nnn\[ORG\]/g' | sed 's/^pn:/nnn\[PERSON\]/g' | sed 's/^ro:/nnn\[ROLE\]/g' | sed 's/^it:/nnn\[IRT\]/g' |
          sed 's/mt:/nnn\[MNTNER\]/g' | sed 's/an:/nnn\[ASN\]/g' | sed 's/on:/-/' |
          sed 's/an:/-/' | sed 's/de:/de~/' | sed 's/ph:/ph~/' | sed 's/ad:/ad~/' | sed 's/cy:/,/' | sed 's/mb:/|/' |
          sed 's/nh:/|/' | sed 's/og:/org~/' | sed 's/am:/|/' | sed 's/em:/|/' | cut -d ':' -f 2- | sed 's/^[ \t]*//;s/[ \t]*$//' |
          tr '[:space:]' ' ' | sed 's/nnn/\n\n\n\n/g' | sed 's/de~/\n\n/' | sed 's/de~//g' | sed 's/ad~/\n\n/' |
          sed 's/org~/| Org:/g' | sed 's/ad~//g' | sed 's/admin~/\n\nAdmin:/' | sed 's/admin~//g' | sed 's/ph~/\n\n/' | sed 's/ph~//g' |
          sed 's/^ *//' | sed 's/\]/\] /' | sed 's/ , /, /g' | sed '/./,$!d' | tee -a ${out}; echo '' | tee -a ${out};
        elif [ $option_poc = "2" ]; then
          whois -h whois.$rir.net "-B ${x}" | sed '/RIPE-NCC-LEGACY-MNT/d' | sed '/RIPE-NCC-HM-MNT/d' > $temp/whois
          f_POC "$temp/whois" | tee -a ${out};
        fi
      else
       echo -e "\nPlease enter a valid RIR database contact object.\n"
     fi
    fi
    done
  else
    echo -e "\nPlease enter a valid RIR database contact object.\n"
  fi
  echo ''; unset rir
fi
unset target_type; unset x; f_Menu
;;
#-------------------------------  PWHOIS.ORG BULK LOOKUP  -------------------------------
w3)
f_makeNewDir ; f_Long; target_type="other"
echo -e "\n${B}pwhois.org Bulk Lookup (IPv4/IPv6)\n"
echo -e -n "\n${B}Target > ${D}PATH TO FILE ${B}>>${D}   " ; read input
echo -e -n "\n${B}Set   > ${D}OUTPUT - FILE NAME  ${B}>>${D}  " ; read filename
out="${outdir}/WHOIS/${filename}.txt"
grep -sEo "[0-9]{1,11}" $input | sort -ug > $temp/asns
if [[ $(grep -sEac "\.|:|/" $input) -gt 0 ]]; then
echo -e "\n${B}Option > Output Formatting (pwhois.org IP address lookups only)\n"
echo -e "${B} [1]${D}  Default" ; echo -e "${B} [2]${D}  Type Cymru (Table Layout)"
echo -e "${B} [3]${D}  BOTH" ; echo -e -n "\n${B}  ?${D}  " ; read option_pwhois
if [ $option_pwhois = "1" ] || [ $option_pwhois = "3" ] ; then
f_pwhoisBULK "${input}" | tee -a ${out}; fi
if [ $option_pwhois = "2" ] || [ $option_pwhois = "3" ] ; then
f_Long | tee -a ${out}; f_WHOIS_TABLE  "$input"; cat $temp/whois_table.txt | tee -a ${out}; fi; fi
if [ -f $temp/asns ]; then
f_HEADLINE "ASNs" | tee -a ${out}
for a in $(cat $temp/asns); do
$DIG +short as${a}.asn.cymru.com TXT | tr -d '"' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/|/G'; done | tee -a ${out}; fi
echo ''; unset target_type; unset x; f_removeDir; f_Menu
;;
#-------------------------------  DOMAIN WHOIS LOOKUP  -------------------------------
w4)
f_makeNewDir ; f_Long; target_type="whois_target"; domain_enum="false"
out="${outdir}/WHOIS.DOMAINS.${file_date}.txt"
echo -e -n "\n${B}Target  >  [1]${D}  Set Target  ${B}|  [2]${D}  Read from file  ${B}?${D}  " ; read -r option_target
f_setTARGET; f_HEADLINE "DOMAIN WHOIS STATUS  |  $file_date" | tee -a ${out}
echo -e "Checking ...\n" | tee -a ${out}; cat $temp/targets.list | tee -a ${out}
for x in $(cat $temp/targets.list); do
f_WHOIS_STATUS "$x"; done | tee -a ${out}
if [ -f $temp/domains_ipv4 ] && [[ $(wc -l < $temp/targets.list) -gt 2 ]]; then
echo '' | tee -a ${out}; f_HEADLINE2 "IP ADDRESSES\n" | tee -a ${out}; f_printADDR "$(cat $temp/domains_ipv4)" | tee -a ${out}; fi
echo ''; unset target_type; unset x; f_removeDir; f_Menu
;;
#-------------------------------  WEB SERVERS  -------------------------------
web|www)
f_makeNewDir; f_Long; f_optionsWWW; echo -e -n "\n${B}    ?${D}   "; read -r op
if [ $op = "1" ] || [ $op = "2" ]; then
  target_type="web"; domain_enum="false"
  if [ $option_connect = "0" ] && [ $op = "1" ]; then
    echo -e "\n${R}Option not available in non-target-connect mode${D}\n"
  else
    echo -e -n "\n${B}Target  >  [1]${D}  Set Target  ${B}|  [2]${D}  Read from file  ${B}?${D}  " ; read -r option_target
     f_setTARGET
  fi 
  if [ -f $temp/targets_name ] || [ -f $temp/targets_ip ]; then
    [[ -f $temp/targets_name ]] && cat $temp/targets_name > $temp/web_targets
    [[ -f $temp/targets_ip ]] && cat $temp/targets_ip >> $temp/web_targets
    if [ $op = "2" ]; then
      if [ $option_connect = "0" ]; then
        header_source="3"
      else
        echo -e "\n${B}Options  > ${C} Dump HTTP Headers ${B} > Source\n"
        echo -e "${B} [1]${D}  cURL  (UserAgent:  Mozilla5.0)"
        echo -e "${B} [2]${D}  cURL  (UserAgent:  cURL)"
        echo -e "${B} [3]${D}  hackertarget.com API"
        echo -e -n "\n${B}  ? ${D}  " ; read -r header_source
        [[ $header_source = "1" ]] && curl_ua="-A $ua_moz" || curl_ua=""
      fi
    elif [ $op = "1" ] && [ $option_connect != "0" ]; then
      default_ttl=$($PING -c 1 127.0.0.1 | grep -so "ttl=.[0-9]${2,3}" | cut -s -d '=' -f 2 | tr -d ' ')
      header_source="1"; option_starttls="0"; tls_port="443"; ssl_diag="true"; send_ping="true"
      echo -e "\n${B} Options  > ${C} Website, Nmap Scan\n"
      echo -e "${B} [1]${D}  Show more website related data"
      echo -e "${B} [2]${D}  Nmap Port/Vulners Scan"
      echo -e "${B} [3]${D}  BOTH"; echo -e "${R} [0]${D}  SKIP"
      echo -e -n "\n${B}   ?${D}  "; read option_web_test
      [[ $option_web_test = "1" ]] || [[ $option_web_test = "3" ]] && page_details="true" || page_details="false"
      echo -e "\n${B}Options >${C} WhatWeb Website Data${B}\n"
      echo -e " ${B}[1]${D}  hackertarget.com API"
      echo -e " ${B}[2]${D}  Local App"
      echo -e " ${R}[0]${D}  SKIP"; echo -e -n "\n${B}    ?${D}  "; read -r ww_source
      [[ $ww_source = "0" ]] && ww="false" || ww="true"
      if [ $option_web_test = "2" ] || [ $option_web_test = "3" ]; then  # Nmap
        declare -a nmap_array=()
        echo -e "\n\n${B}Options  > ${C}Nmap Target Ports\n"
        echo -e "${B} [1]${D}  Common web ports & ports found via Shodan (if applicable)"
        echo -e "${B} [2]${D}  All TCP ports"
        echo -e "${B} [3]${D}  Customize ports"; echo -e -n "\n${B}  ? ${D}  " ; read option_ports
        if [ $option_ports = "2" ]; then
          ports="-p-"
        elif [ $option_ports = "3" ]; then
          echo -e -n "\n${B}Set     > Ports  ${D}- e.g. 636,989-995  ${B}>>${D} "; read -r ports_input
          ports="-p $(echo $ports_input | tr -d ' ')"
        fi
        echo -e "\n\n${B} Options  > ${C}Nmap Scripts - Aggression Level\n"
        echo -e "${B} [0]${D}  Safe Mode  (Uses Nmap Script from category 'safe' only)"
        echo -e "${B} [1]${D}  Level 1    (0 + CORS, http methods & SSH algos)"
        echo -e "${B} [2]${D}  Level 2    (0 & 1 + scraping of server directories, mySQL empty root password check)"
        echo -e "${B} [3]${D}  Level 3    (0, 1 & 2 + dombased & stored XSS check)"
        echo -e -n "\n${B}  ?${D}   " ; read option_scripts
        [[ $option_scripts = "0" ]] && script_choice="${web0}" || script_args="--script-args=http-methods.test-all"
        [[ $option_scripts = "1" ]] && script_choice="${web0},${web1}"
        [[ $option_scripts = "2" ]] && script_choice="${web0},${web1},${web2}"
        [[ $option_scripts = "3" ]] && script_choice="${web0},${web1},${web2},${web3}"
        if [ -n "$is_admin" ]; then
          scripts="--script=${script_choice},vulners"
          nmap_array+=(-sS -sV -O --osscan-limit --version-intensity 5 -Pn -R --resolve-all --open)
        else
          scripts="--script=${script_choice}"; nmap_array+=(-sT -Pn -R --resolve-all --open)
        fi
      fi # Nmap
    fi # config op = 1
    for x in $(cat $temp/web_targets); do
      f_CLEANUP_FILES; f_getTYPE "$x"
      if [ $op = "1" ]; then
        out="${outdir}/WEBSRV_HealthCheck.${file_date}_${x}.txt"
        f_HEADLINE3 "[WEB]  HEALTH CHECK  |  $x  |  $file_date" | tee -a ${out}
      else
        out="${outdir}/HTTP_HEADERS.${x}.txt"; f_HEADLINE3 "[HTTP HEADERS]  $x   ($file_date)" | tee -a ${out}
      fi
      #------ op 3 (header_source: hackertarget.com API) ------
      if [ $op = "2" ] && [ $header_source = "2" ]; then
        [[ -f $temp/ip4.list ]] && echo '' && f_printADDR "$(cat $temp/ip4.list)" | tee -a ${out}
        [[ -f $temp/ip6.list ]] && echo '' && f_printADDR "$(cat $temp/ip6.list)" | tee -a ${out}
        f_getHEADERS "$x"; f_HEADERS "$x" | tee -a ${out}
      else
        declare -a curl_array=() ; curl_array+=(-sLkv)
        error_code=6; f_CURL_WRITEOUT "$x"
        if [ $? = ${error_code} ]; then
          echo -e "${R}$x  WEBSITE CONNECTION: FAILURE${D}\n"
          webpresence="false"; echo -e "\n $x WEBSITE CONNECTION: FAILURE\n" >> ${out}
        else
          webpresence="true"
          echo -e "\nWEB CONNECT:     ${G}SUCCESS${D}"
          if [ $op = "2" ]; then
            [[ -f $temp/ip4.list ]] && echo '' && f_printADDR "$(cat $temp/ip4.list)" | sed 's/^/ /' | tee -a ${out}
            [[ -f $temp/ip6.list ]] && echo '' && f_printADDR "$(cat $temp/ip6.list)" | sed 's/^/ /' | tee -a ${out}
            f_getHEADERS "$x"; echo '' | tee -a ${out}; f_HEADERS "$x" | tee -a ${out}
          else # $op = 1
            f_getWEB_INFO "$x" | tee -a ${out}
            f_PAGE | tee -a ${out}
            target_host=$(f_getWEBHOST)
            [[ -f $temp/web4 ]] && v4_unique=$(f_EXTRACT_IP4 "$temp/web4"); [[ -f $temp/web6 ]] && v6_unique=$(f_EXTRACT_IP4 "$temp/web6")
            [[ $(f_countW "$temp/web_ips") -gt 1 ]] && f_SERVER_INSTANCES | tee -a ${out} && f_WEB_PING | tee -a ${out}
            cat $temp/hndshake > ${outdir}/HANDSHAKES.${target_host}.${file_date}.txt
            f_WEBHOST_INFO | tee -a ${out}  #-----  Geolocation, BGP, Shodan, IP reputation  -----
            if [ $option_web_test = "2" ] || [ $option_web_test = "3" ]; then  #-----  Nmap scan  -----
             echo ''; f_Long; echo -e "\nRunning Nmap Scan ...\n"
              if [ $option_ports = "1" ]; then
                if [ -f $temp/detected_ports ]; then
                  echo -e "22\n3306\n8080\n8443" >> $temp/detected_ports
                  ports_probe=$(sort -ug $temp/detected_ports | sed 's/^/,T:/' | tr '[:space:]' ' ' | tr -d ' ' | sed 's/^\,//')
                  echo -e "Scanning the following ports - $ports_probe\n"; ports="-p $ports_probe"
                else
                  ports="$ports_web"
                fi
              fi
              [[ -n "$v4_unique" ]] && opt_v6='' && f_RUN_NMAP "$target_host" | tee -a ${out}
              [[ -n "$v6_unique" ]] && opt_v6='-6' && f_RUN_NMAP "$target_host" | tee -a ${out}
            fi
            #----- SSL  -----
            declare ssl_array1; ssl_array1+=(-servername $target_host -verify_hostname $target_host)
            f_CERT_INFO "$target_host" | tee -a ${out} 
            f_PAGE_ADDITIONS "$target_host" | tee -a ${out}
          fi # $op = 1
        fi # website connection: failure
      fi # [ $op != "2" ] && [ $header_source != "2" ]
    done 
  fi # [ -f $temp/targets_name ] || [ -f $temp/targets_ip ]
 fi # [ $op = "1" ] || [ $op = "2" ] 
target_type=""; x="0"; unset rir
f_removeDir; f_Menu
;;
#-------------------------------  GENERAL/FUZZY TARGET SEARCH  -------------------------------
x|fuzzy)
f_makeNewDir; f_Long; rir=""; target_type=""; option_connect="0"
echo -e "\n${B}TARGET INFO >\n"
echo -e "EXPECTED INPUT\n"
echo -e "ASNs|AS-Sets|AS-Sets|Hostnames|IPs|Network Addresses & Names|OrgIDs|MAC Addr.\n"
echo -e "${R}Not supported:${D} Admin-c IDs (nic-hdl), role or person names (supported by option w1)"
echo -e -n "\n${B}Options    >  [1]${D}  Set target  ${B}| [2]${D}  Target list  ${B}| [0]${D}  Back to the ${B}main menu ?${D}  " ; read -r option_target
if [ $option_target != "0" ]; then
  f_setTARGET; domain_enum="false"; option_netdetails2="0"; option_netdetails5="0"; threat_enum="false"
  if [ -f $temp/targets_ip ] || [ -f $temp/targets_nets ] || [ -f $temp/targets_name ]; then
    echo -e "\n${R}${bold}IP HOSTS/NETS:${D}  Excessive queries for contact details may result in a temporary ban from accessing whois services\n"
  fi
  if [ -f $temp/targets_ip ] || [ -f $temp/targets_nets ] || [ -f $temp/targets_name ] || [ -f $temp/targets_asn ]; then
    echo -e "\n${B}Options  > ${C}ASN|IP|NETWORK DETAILS\n"
    echo -e "${B} [1]${D}  Target objects OVERVIEW"
    echo -e "${B} [2]${D}  Target objects DETAILS"
    echo -e -n "\n${B}  ? ${D}  " ; read -r lod
    [[ $lod = "2" ]] && option_detail="2" || option_detail="1"
    if [ -f $temp/targets_name ] && [ $lod = "2" ]; then
      echo -e "\n\n${B} Options >${C} WEBSITE INFO (if applicable) ${D}\n"
      echo -e "${B} [1]  ${C}API${D} urlscan.io"
      echo -e "${B} [2]  ${C}API${D} WhatWeb (via hackertarget.com)"
      echo -e "${B} [3]  ${D}BOTH"
      echo -e "${R} [0]  ${D}SKIP"; echo -e -n "\n${B}  ? ${D}  " ; read -r webinfo
      if [ $webinfo = "1" ] || [ $webinfo = "3" ]; then
        uscan="true"
      fi
      if [ $webinfo = "2" ] || [ $webinfo = "3" ]; then
        ww="true"; ww_source="1"
      fi
    fi
  fi
  #************** MACs **************
  if [ -f $temp/targets_mac ]; then
    if [ -f /usr/share/nmap/nmap-mac-prefixes ]; then
      target_input=$(cat $temp/targets_mac)
      f_HEADLINE2 "MAC ADDRESS VENDOR LOOKUP"
      for x in $(cat $temp/targets_mac); do echo -e "\n\n* $x\n\n  $(f_getMAC_PFX "$x")"; done
    else
      echo -e "\nFile 'nmap-mac-prefixes not found\n"
    fi
  fi;  x=""
  #************** ASNs **************
  if [ -f $temp/targets_asn ]; then
    target_input=$(cat $temp/targets_asn)
    target_type="as"; [[ $lod = "1" ]] &&  out="${outdir}/ASN_SUMS.file_date.txt"
    f_printTARGET_TYPE "ASNs"
    for x in $(cat $temp/targets_asn); do
      if [ $lod = "1" ]; then
        echo '' | tee -a ${out}; f_AS_SHORT "$x" | tee -a ${out}
      else
        out="${outdir}/AS_DETAILS.${file_date}_AS${x}.txt"; f_AS_INFO "$x" | tee -a ${out}
      fi
      f_CLEANUP_FILES; x=""; as_rir=""; f_CLEANUP_FILES; done
  fi;  x=""
#************** AS SETs **************
  if [ -f $temp/targets_as_set ]; then
    target_input=$(cat $temp/targets_as_set)
    target_type="as_set"; out="${outdir}/AS_SETS.file_date.txt"; f_printTARGET_TYPE "AS-SETS"
    for x in $(cat $temp/targets_as_set); do
      echo ''; f_AS_SET "$x"; x=""; f_CLEANUP_FILES
    done | tee -a ${out}
  fi; x=""
  #************** Hostnames **************
  if [ -f $temp/targets_name ]; then
    [[ -f $temp/ips_all ]] && rm $temp/ips_all; target_input=$(cat  $temp/targets_name)
    target_type="hostname"; f_printTARGET_TYPE "HOSTNAMES"
    [[ $lod = "1" ]] && out="${outdir}/HOSTNAMES_SUM.${file_date}.txt" || include_subs="false"
    for x in $(cat $temp/targets_name); do
      f_CLEANUP_FILES; f_getTYPE "$x"; host_domain=$(f_EXTRACT_HOSTN "$temp/host_domain")
      if [ $lod = "2" ]; then
        echo ''; out="${outdir}/HOST_${x}_${file_date}.txt"; f_HEADLINE3 " [HOST]   $x   ($file_date)" | tee -a ${out}
      else
        f_Long2 | tee -a ${out}
      fi
      f_HOST_DNS "$x" | tee -a ${out}
      if [ $lod = "2" ]; then
        echo '' | tee -a ${out}; f_Long | tee -a ${out}; f_WHOIS_STATUS "$x" | tee -a ${out}
        f_EXTRACT_IP4 "$temp/host_ips" | tee $temp/ips_all > $temp/web4; f_EXTRACT_IP6 "$temp/host_ips" | tee -a $temp/ips_all > $temp/web6
        [[ $ww = "true" ]] && f_getWHATWEB "$x" && f_WHATWEB | tee -a ${out} | tee -a ${out}
        if [ -f $temp/web4 ]; then
          threat_enum="true"; target_type="default"
          for a in $(f_EXTRACT_IP4 "$temp/web4"); do f_BOGON "$a"; f_HOST_DEFAULT "$a"; done | tee -a ${out}
        elif  [ -f $temp/web6 ]; then
          target_type="default"; for z in $(f_EXTRACT_IP6 "$temp/web6"); do f_BOGON "$z"; f_HOST_DEFAULT "$z"; done | tee -a ${out}
        fi
        [[ $uscan = "true" ]] && f_getURLSCAN "$x" && f_HEADLINE2 "urlscan.io\n" | tee -a ${out} && f_printURLSCAN "$x" | tee -a ${out} 
        f_CERT_SPOTTER "$x" | tee -a ${out}
      fi
    done
    if [ -f $temp/hosts_all ]; then
      echo '' | tee -a ${out}; f_HEADLINE2 "TARGET IP ADDRESSES" | tee -a ${out}
      h_4=$(f_EXTRACT_IP4 "$temp/hosts_all"); [[ -n "$h_4" ]] && echo '' && f_printADDR "$h_4" | tee -a ${out}
      h_6=$(f_EXTRACT_IP6 "$temp/hosts_all"); [[ -n "$h_6" ]] && echo '' && f_printADDR "$h_6" | tee -a ${out}
    fi
  fi; x=""
  #************** IP Addresses **************
  if [ -f $temp/targets_ip ]; then
    target_input=$(cat $temp/targets_ip)
    target_type="default";  f_printTARGET_TYPE "IP ADDRESSES"
    for x in $(cat $temp/targets_ip); do
      f_CLEANUP_FILES; f_getTYPE "$x"; file_name=$(echo $x | tr ':' '.' | tr '/' '_' | tr -d ' ')
      out="${outdir}/IP_${file_date}_${file_name}.txt"
      echo '' | tee -a ${out}; f_HOST_DEFAULT "$x" | tee -a ${out}; echo '' | tee -a ${out}; rir=""
    done
  fi; x=""
  #************** Networks **************
  if [ -f $temp/targets_nets ]; then
    target_input=$(cat $temp/targets_nets)
    target_type="net"; net_report="false"
    f_printTARGET_TYPE "NETWORKS"
    for x in $(cat $temp/targets_nets); do
      f_CLEANUP_FILES; f_getTYPE "$x"; file_name=$(echo $x | tr ':' '.' | tr '/' '_' | tr -d ' ')
      out="${outdir}/NET_INFO.${file_date}_${file_name}.txt"
      f_WHOIS_NET "$x" | tee -a ${out};  echo '' | tee -a ${out}; rir=""
    done
  fi; x=""
  #************** Org-IDs / Network Names **************
  if [ -f $temp/targets_other ]; then
    option_detail="1"; target_type="other"; rir="any"
    target_input=$(cat $temp/targets_other); f_printTARGET_TYPE "NETWORK NAME or ORG ID"
    for x in $target_input; do
      f_CLEANUP_FILES; out="${outdir}/TARGET_INFO_${x}.txt"
      f_SEARCH_COMPLETE "$x" | tee -a ${out}
      echo -e "Searching pwhois.org by org-id ...\n" | tee -a ${out}
      f_PWHOIS_ORG "$x" | tee -a ${out}
      echo -e "Searching pwhois.org by org-name ...\n" | tee -a ${out}
      f_PWHOIS_ORG_NAME "$x" | tee -a ${out}
      # *******************  REGISTRY WHOIS (ALL RIRS)  *******************
      f_ALL_SOURCES_WHOIS "$x"
      resource_type=$(grep -sawi "$x" $temp/all_sources | cut -s -d ':' -f 1 | sort -u | tr '[:space:]' ' ' | sed 's/ /  /g' |
      sed 's/^ *//' | sed 's/netname/Net-Name/' | sed 's/org/Org-Id/'; echo '')
      if [ -n "$resource_type" ]; then
        rirs_all=$(f_VALUE ":" "$(grep -sa '^source:' $temp/all_sources)" | grep -sEo "ARIN|RIPE|APNIC|AFRINIC" | sort -u)
        print_rirs=$(echo "$rirs_all" | tr '[:space:]' ' '  | sed 's/^ *//'; echo '')
        netcount_total=$(grep -sac '^netname:' $temp/all_sources); orgcount_total=$(grep -sEac "^org:|^organisation:" $temp/all_sources)
        f_EXTRACT_EMAIL "$temp/all_sources" > $temp/mail_all
        if [[ $netcount_total -gt 0 ]]; then
          f_VALUE ":" "$(grep -sa '^netname:' $temp/all_sources)" | tr -d ' ' | sort -uV > $temp/netnames
          print_netnames=$(cat $temp/netnames | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//')
        fi
        if [[ $orgcount_total -gt 0 ]]; then
          f_VALUE ":" "$(grep -sEa "^org:|^mnt-irt:|^organisation:" $temp/all_sources)" | tr -d ' ' | sort -uV > $temp/orgs_all
          org_count=$(wc -w < $temp/orgs_all)
          print_orgs_all=$(cat $temp/orgs_all | tr '[:space:]' ' ' | sed 's/ /  /g' | sed 's/^ *//')
        else
          org_count=0
        fi
        f_HEADLINE3 "[WHOIS]  $x  -  $file_date" | tee -a ${out}
        echo -e "\nType:         $resource_type" | tee -a ${out}
        echo -e "\nRIRs:         $print_rirs" | tee -a ${out}
        echo -e "\nResources:    Nets: $netcount_total,  Orgs: $org_count" | tee -a ${out}
        [[ $netcount_total -gt 0 ]] && echo -e "\n\nNet-Names:    $print_netnames" | tee -a ${out}
        [[ $org_count -gt 0 ]] && echo -e "\nOrg-Ids:      $print_orgs_all" | tee -a ${out}
        if [ -f $temp/mail_all ] && [[ $(wc -w < $temp/mail_all) -gt 0 ]]; then
          mail_all=$(cat $temp/mail_all | tr '[:space:]' ' ' | sed 's/ /  /g' | fmt -w 60)
          if [[ $(wc -w < $temp/mail_all) -lt 4 ]]; then
            echo -e "\nEmail:        $mail_all\n" | tee -a ${out}
          else
            echo -e "\n\nEMAIL\n" | tee -a ${out}; echo -e "$mail_all" | sed G | tee -a ${out}
          fi
        fi
        # *******************  ARIN  *******************
        sed -e '/./{H;$!d;}' -e 'x;/ARIN/!d' $temp/all_sources > $temp/arin_nets
        if [[ $(grep -c 'ARIN' $temp/arin_nets) -gt 0 ]]; then
          rir="arin"
          arin_orgs=$(f_VALUE ":" "$(grep -sai '^org:' $temp/arin_nets)" | sort -uV)
          f_HEADLINE3 "[ARIN]   $x" | tee -a ${out}
          if [ -n "$arin_orgs" ]; then
            echo -e "\nORGANISATIONS\n" | tee -a ${out}
            for og in $arin_orgs; do
              $WHOIS -h whois.arin.net "e + $og" > $temp/org_tmp; f_POC $temp/org_tmp
            done | tee -a ${out}
            echo '' | tee -a ${out}
          fi
          f_sortNETS "$x" | tee -a ${out}
        fi
        # *******************  RIPE  *******************
        sed -e '/./{H;$!d;}' -e 'x;/RIPE/!d' $temp/all_sources > $temp/resources_ripe
        if [[ $(grep -c 'RIPE' $temp/resources_ripe) -gt 0 ]]; then
          rir="ripe"; sed -e '/./{H;$!d;}' -e 'x;/netname:/!d' $temp/resources_ripe |
          grep -sEa "^inet(6)?num:|^netname:|^country:|^org:|^admin-c:|^mnt-by:|^source:" | sed '/source:/G' > $temp/nets
          if [[ $(grep -c 'netname:' $temp/nets) -gt 0 ]]; then
            ripe_admins=$(f_VALUE ":" "$(grep -sa '^admin-c:' $temp/nets)" | tr -d ' ' | sort -u)
          fi
          ripe_orgs=$(f_VALUE ":" "$(grep -sEa "^org:|^orgname:" $temp/resources_ripe)" | sort -uV)
          f_HEADLINE3 "[RIPE]   $x" | tee -a ${out}; echo '' | tee -a ${out}
          [[ -n "$ripe_orgs" ]] || [[ -n "$ripe_admins" ]] && echo -e "\nCONTACT\n" | tee -a ${out}
          if [ -n "$ripe_orgs" ]; then
            for og in $ripe_orgs; do
              $TOUT 15 $WHOIS -h whois.ripe.net -- "--no-personal $og" > $temp/org_whois
              echo ''; f_ORG_SHORT "$temp/org_whois"; echo ''
            done | tee -a ${out}
          fi
          if [ -n "$ripe_admins" ]; then
            for ac in $ripe_admins; do echo ''; f_ADMIN_C "$ac"; echo ''; done | tee -a ${out}
          fi
          [[ -f $temp/nets ]] && echo '' | tee -a ${out} && f_sortNETS "$x" | tee -a ${out}
        fi
        # *******************  APNIC  *******************
        sed -e '/./{H;$!d;}' -e 'x;/APNIC/!d' $temp/all_sources > $temp/resources_apnic
        if [[ $(grep -c 'APNIC' $temp/resources_apnic) -gt 0 ]]; then
          rir="apnic"; sed -e '/./{H;$!d;}' -e 'x;/netname:/!d' $temp/resources_apnic |
          grep -sEa "^inet(6)?num:|^netname:|^country:|^org:|^abuse-c:|^admin-c:|^mnt-by:|^source:" | sed '/source:/G' > $temp/nets
          f_HEADLINE3 "[APNIC]   $x" | tee -a ${out}; echo '' | tee -a ${out}
          apnic_admins=$(f_VALUE ":" "$(grep -sEa "^abuse-c:|^admin-c:" $temp/nets)" | tr -d ' ' | sort -uV)
          apnic_orgs=$(f_VALUE ":" "$(grep -sai '^org:' $temp/apnic_nets)" | sort -uV)
          [[ -n "$apnic_orgs" ]] || [[ -n "$apnic_admins" ]] && echo -e "\nCONTACT\n" | tee -a ${out}
          if [ -n "$apnic_orgs" ]; then
            for og in $apnic_orgs; do
              $TOUT 15 $WHOIS -h whois.apnic.net -- "--no-personal $og" > $temp/org_whois
              echo ''; f_ORG_SHORT "$temp/org_whois"; echo ''
            done | tee -a ${out}
          fi
          if [ -n "$apnic_admins" ]; then
            for ac in $apnic_admins; do echo ''; f_ADMIN_C "$ac"; echo ''; done | tee -a ${out}
            echo '' | tee -a ${out}; f_sortNETS "$x" | tee -a ${out}; rm $temp/nets
          fi
        fi
        # *******************  AFRINIC  *******************
        sed -e '/./{H;$!d;}' -e 'x;/AFRINIC/!d' $temp/all_sources > $temp/resources_afrinic
        if [[ $(grep -c 'AFRINIC' $temp/resources_apnic) -gt 0 ]]; then
          rir="afrinic"; sed -e '/./{H;$!d;}' -e 'x;/netname:/!d' $temp/resources_afrinic |
          grep -sEa "^inet(6)?num:|^netname:|^country:|^org:|^abuse-c:|^admin-c:|^mnt-by:|^source:" | sed '/source:/G' > $temp/nets
          f_HEADLINE3 "[AFRINIC]   $x" | tee -a ${out}; echo '' | tee -a ${out}
          afrinic_admins=$(f_VALUE ":" "$(grep -sEa "^abuse-c:|^admin-c:" $temp/nets)" | tr -d ' ' | sort -uV)
          afrinic_orgs=$(f_VALUE ":" "$(grep -sai '^org:' $temp/apnic_nets)" | sort -uV)
          [[ -n "$afrinic_orgs" ]] || [[ -n "$afrinic_admins" ]] && echo -e "\nCONTACT\n" | tee -a ${out}
          if [ -n "$afrinic_orgs" ]; then
            for og in $afrinic_orgs; do
              $TOUT 15 $WHOIS -h whois.afrinic.net -- "--no-personal $og" > $temp/org_whois
              echo ''; f_ORG_SHORT "$temp/org_whois"; echo ''
            done | tee -a ${out}
          fi
          if [ -n "$afrinic_admins" ]; then
            for ac in $afrinic_admins; do echo ''; f_ADMIN_C "$ac"; echo ''; done | tee -a ${out}
              echo '' | tee -a ${out}; f_sortNETS "$x" | tee -a ${out}; rm $temp/nets
          fi
        fi
      else
      # *******************  ARIN  *******************
      $TOUT 20 $WHOIS -h whois.arin.net e $x | grep -Ev "#|No match" | grep ':' > $temp/arin_org
      if [ -f $temp/arin_org ] && [[ $(grep -oc "$x" $temp/arin_org) -gt 0 ]]; then
        f_HEADLINE3 "[ARIN WHOIS]  $x  CONTACT" | tee -a ${out}; f_POC $temp/arin_org; echo "$x" >> $temp/orgs_all
      fi
    fi # [ -n $resource_type ]
      if [ -f "$temp/orgs_all" ]; then
        for oid in $(sort -u $temp/orgs_all); do echo '' ; f_netBLOCKS "$oid"; done | tee -a ${out}
      fi
      f_CLEANUP_FILES
    done
  fi; x=""
  echo ''; f_Long; f_targetCONNECT; echo ''
fi # option_target != 0
f_removeDir; f_Menu
;;
q|Q)
echo -e "\n${B}----------------------------------- Done -------------------------------------\n"
echo -e "                       ${B}Author - Thomas Wy, Nov 2023${D}\n\n" ; f_removeDir
unset outdir; unset output_folder; unset report; unset x; unset as; unset option_target; unset nssrv; unset rir
unset conn; unset option_connect; unset target_type; unset domain_enum; unset threat_enum; unset option_source
break
;;
esac
done

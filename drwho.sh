#!/bin/bash
#************** colors ***************
B='\033[1;34m'
BDim='\033[0;34m'
D='\033[0m'
GREY='\033[1;30m'
GR='\033[1;32m'
R='\033[1;31m'
T='\033[1;36m'
W='\033[1;37m'

#************** drwho - banner *************

echo -e "${B}\n
 ____                _           
|  _ \ _ ____      _| |__   ___  
| | | | '__\ \ /\ / / '_ \ / _ \ 
| |_| | |   \ V  V /| | | | (_) |
|____/|_|    \_/\_/ |_| |_|\___/ 

${D}"

#**************** Functions ***************

#************ directory containing the output text file*************
function f_makePermDir {
if [ ! -d "$HOME/drwho_results" ]; then
mkdir $HOME/drwho_results
fi
}

#************ create temporary working directory *************
function f_makeNewDir {
if [ -d "drwho_tmp" ]; then
rm -rf drwho_tmp
fi
mkdir drwho_tmp
}

#************ delete temporary working directory *************
function f_removeDir {
if [ -d "drwho_tmp" ]; then
rm -rf drwho_tmp
fi
}

#************ separators (solid, dashed) *************
function f_solidLong {
    echo -e "\n${BDim}________________________________________________________________${D}\n"
}

#************ short horizontal line *************
function f_solidShort {
    echo -e "${BDim}      ____${D}\n"
}

function f_Dashes {
     echo -e "${BDim}------------------------------------------${D}"
}

function f_Dashes_long {
     echo -e "${BDim}------------------------------------------------------------${D}"
}

function f_textfileSeparator {
echo -e "\n__________________________________________________________________________\n" >> $HOME/drwho_results/$file.txt
}

#********************************* mail- & name server IPv4 addresses  *********************************
function f_ipv4 {
    echo -e "\n=== MX A Records ===\n"
            for i in $(echo $mx_url)
            do
                echo | host -t A $i | sed -e s/'has'/'\n'/ | sed s/address//
                echo ''
            done
    echo -e "\n=== NS A Records === \n"
            for i in $(echo $ns_url)
            do
             echo | host -t A $i | sed -e s/'has'/'\n'/ | sed s/address//
             echo ''
           done
}


function f_ipv6 {
    echo -e "\n=== MX AAAA Records ===\n"
        for i in $(echo $mx_url)
        do
            echo | host -t AAAA $i | sed -e s/'has'/'\n'/ | sed s/address//
            echo ''
        done
    echo -e "\n=== NS  AAAA Records ===\n"
            for i in $(echo $ns_url)
            do
                echo |  host -t AAAA $i | sed -e s/'has'/'\n'/ | sed s/IPv6// | sed s/address//
                echo ''
            done
}


#************ certificate status information *************
function f_certInfo {
f_textfileSeparator
echo -e "\n      Certificate Information"      >> $HOME/drwho_results/$file.txt
echo -e "   --------------------------------\n" >> $HOME/drwho_results/$file.txt
timeout 3 openssl s_client -connect $target:443 -brief 2>drwho_tmp/ssl_sum2.txt
echo | timeout 3 openssl s_client -connect $target:443 2> drwho_tmp/status.txt -status >> drwho_tmp/status.txt
echo | timeout 3 openssl s_client -connect $target:443 2>>drwho_tmp/ssl_sum2.txt | openssl x509 -text -enddate >> drwho_tmp/ssl_sum2.txt
cat drwho_tmp/ssl_sum2.txt | tr -d '"' | sed 's/, Inc//' | sed 's/ = /: /g' | sed 's/_/ - /g' | tr -d '(' | tr -d ')' | sed 's/^ *//' > drwho_tmp/ssl.txt
subject=`cat drwho_tmp/ssl.txt | grep -m 1 -w 'Subject:' | sed 's/, Inc//' | sed 's/,/\n/g' | sed 's/Subject://g'`
subject_org=`echo "$subject" | grep -w 'O:' | sed 's/^ *//' | sed 's/O:/O: /'`
subject_country=`echo "$subject" | grep -w 'C:' | tr -d ' ' | sed 's/C:/\/ /'  `
subject_cn=`echo "$subject" | grep -w 'CN:' | sed 's/^ *//'`
issuer=`cat drwho_tmp/ssl.txt | grep -m 1 -w 'Issuer:' | sed 's/, Inc//' | sed 's/,/\n/g'| sed 's/Issuer://g'`
issuer_org=`echo "$issuer" | grep -w 'O:' | sed 's/^ *//' | sed 's/O:/O: /'`
issuer_country=`echo "$issuer" | grep -w 'C:' | tr -d ' ' | sed 's/C:/\/ /'`
protocol=`cat drwho_tmp/ssl.txt | grep -i -m 1 'protocol' | cut -d ':' -f 2-`
cipher=`cat drwho_tmp/ssl.txt | grep -i -m 1 'ciphersuite' | sed s/'AES - '/'AES-'/g | cut -d ':' -f 2-`
algo=`cat drwho_tmp/ssl.txt | grep -i -m 1 'algorithm' | sed s/'With'/' with '/g  | sed s/'Encryption'/' Encryption'/g | cut -d ':' -f 2-`
key_algo=`cat drwho_tmp/ssl.txt | grep -i -m 1 -A 2 'public' | sed '/Info/d' |  sed '/Algorithm:/d'  | sed 's/Public-Key//' | sed 's/ : /, /' | sed 's/^ *//g'`
echo -e -n "Expires:       "      | tee -a $HOME/drwho_results/$file.txt
cat drwho_tmp/ssl.txt | grep -i -m 1 'after' | cut -d ' ' -f 4-  | tee -a $HOME/drwho_results/$file.txt
echo -e "\nSubject:       $subject_cn $subject_country"  | tee -a $HOME/drwho_results/$file.txt
echo -e "\nIssuer:        $issuer_org $issuer_country "  | tee -a $HOME/drwho_results/$file.txt
echo "$issuer" | grep -w 'CN:' | sed 's/^ *//' | sed 's/CN:/               CN:/'      | tee -a $HOME/drwho_results/$file.txt
echo -e "\n\nTLS-Vers.:    $protocol"        | tee -a $HOME/drwho_results/$file.txt
echo -e "\nCipher:       $cipher"    | tee -a $HOME/drwho_results/$file.txt
echo -e "\nSignature:    $algo"      | tee -a $HOME/drwho_results/$file.txt
echo -e "\nPublic Key:    $key_algo\n"   | tee -a $HOME/drwho_results/$file.txt
f_solidLong
f_textfileSeparator
echo -e "${B}Certificate Chain (depth:2-1-0):${D}\n\n"
echo -e "\n=== Certificate Chain (depth:2-1-0) === \n\n" >> $HOME/drwho_results/$file.txt
root_ca=`cat drwho_tmp/ssl.txt | grep -i -m 1 -A 1 'depth=2' | sed 's/depth=2//' | sed 's/,/\n/g' | sed '/L:/d'  | sed '/ST:/d' | sed '/postal/d' |
sed '/street:/d' | sed 's/^ *//' | sed 's/verify/\nverify/' | sed 's/return:/return: /' | sed 's/C:/C:   /' | sed 's/CN:/CN:  /' |   sed 's/O:/O:  /' | sed 's/OU:/OU:  /'`
root_ca_org=`echo "$root_ca" | grep -w 'O:' | sed 's/^ *//' | sed 's/O:/O: /'`
root_ca_country=`echo "$root_ca" | grep -w 'C:' | tr -d ' ' | sed 's/C:/\/ /'`
root_ca_cn=`echo "$root_ca" | grep -w 'CN:' | sed 's/^ *//' `
echo "$root_ca_org $root_ca_country"    | tee -a $HOME/drwho_results/$file.txt
echo "$root_ca_cn"            | tee -a $HOME/drwho_results/$file.txt
echo "$root_ca" | grep -i -w 'verify' | sed 's/return://' | sed 's/verify/      verify/' | tee -a $HOME/drwho_results/$file.txt
echo -e "\n" | tee -a $HOME/drwho_results/$file.txt
ca=`cat drwho_tmp/ssl.txt | grep -i -m 1 -A 1 'depth=1' | sed 's/depth=1//' | sed 's/,/\n/g' | sed '/L:/d'  | sed '/ST:/d' | sed '/postal/d' |
sed '/street:/d' | sed 's/^ *//' | sed 's/verify/verify/' | sed 's/return:/return: /' | sed 's/C:/C:   /' | sed 's/CN:/CN:  /' |   sed 's/O:/O:  /' |
sed 's/OU:/OU:  /'`
ca_org=`echo "$ca" | grep -w 'O:' | sed 's/^ *//' | sed 's/O:/O: /'`
ca_country=`echo "$ca" | grep -w 'C:' | tr -d ' ' | sed 's/C:/\/ /'`
ca_cn=`echo "$ca" | grep -w 'CN:' | sed 's/^ *//'`
echo "$ca_org $ca_country"     | tee -a $HOME/drwho_results/$file.txt
echo "$ca_cn"                  | tee -a $HOME/drwho_results/$file.txt
echo "$ca" | grep -i -w 'verify' | sed 's/return://' | sed 's/verify/      verify/' |  tee -a $HOME/drwho_results/$file.txt
echo -e "\n" | tee -a $HOME/drwho_results/$file.txt
echo "$subject_cn" | sed 's/CN:/CN:  /' | tee -a $HOME/drwho_results/$file.txt
cat drwho_tmp/ssl.txt | grep  -i -w -m 1 -A 1 'Constraints:' | sed "/constraints:/d" | sed "/Constraints:/d" | sed 's/CA:/CA:   /' | tee -a $HOME/drwho_results/$file.txt
}

#************************** dump server certificate files *********************************
function f_showCerts {
echo -e "=== $target Certificates ===\n"
date
echo -e "\n"
timeout 3 openssl s_client -connect $target:443 -showcerts
echo -e "\n________________________________________________________________\n"
echo -e "\n$target Public Key${T}\n\n"
timeout 3 openssl s_client -connect $target:443 2>>/dev/null | openssl x509 -pubkey -noout
echo -e "${D} \n"
}

#************************** HTTP- headers summary *********************************
function f_headers {
    echo -e "$target HTTP-Headers Summary \n"     >> $HOME/drwho_results/$file.txt
    curl -s -I -L --max-time 3 $target > drwho_tmp/headers.txt
    cat drwho_tmp/headers.txt | sed '/[Hh][Ii][Tt]/d' | sed '/[Mm][Ii][Ss][Ss]/d' | sed '/[Dd][Aa][Tt][Ee]:/d' |
    sed '/{/d' | sed '/}/d' | sed '/[Rr]eport*/d' | sed '/[Vv]ary/d' | sed '/[Cc]ontent-[Tt]ype:/d' |
    sed '/[Cc]ache-[Cc]ontrol/d' | sed '/[Ee]-[Tt][Aa][Gg]:/d' | sed '/[Ee][Tt][A#a][Gg]/d' | sed '/[Aa]ge:/d' |
    sed '/[Cc]ontent-[Ll]ength:/d' |  sed '/[Ss]et-[Cc]ookie/d' | sed '/[Cc]ontent-[Ss]ecurity-[Pp]olicy:/d' |
    sed '/X-UA-Compatible/d' | sed '/x-ua-compatible/d' |sed '/[Aa]ccept-[Rr]anges/d' | sed '/[Xx]-[Dd]ownload-[O#o]ptions/d' |
    sed '/[Xx]-[Tt]imer/d' | sed '/max_age/d' | sed '/[Ff]eature-[Pp]olicy/d' | sed '/[Xx]-[Cc]ache-*/d' | sed '/x-tzla/d'  |
    sed '/[Ee]xpect-[Cc][Tt]:/d' | sed '/[Ll]ast-[Mm]odified:/d'  | sed '/NEL:/d' | sed '/-src/d' | sed '/[Xx]-[Vv]cs/d' |
    sed '/[Xx]-[Vv][Cc][Ss]-*/d' | sed '/[Vv]ia:/d' | sed '/[Xx]-[Rr]equest-[Ii]d:/d' | sed '/[Ss]trict-[Tt]ransport-[Ss]ecurity:/d' |
    sed '/[Ee]xpires:/d' | sed '/[Xx]-[Ff]rame-[Oo]ptions:/d' | sed '/[Xx]-[Ss]erved-[Bb]y:/d' | sed '/req-svc-chain:/d' |
    sed '/[Rr]etry-[Aa]fter:/d' | sed '/[Kk]eep-[Aa]live:/d' | sed '/href=*/d' | sed '/[Ll]ink:/d' | sed '/[Cc]onnection:/d' |
    sed '/[Aa]ccess-[Cc]ontrol-[Aa]llow-[Oo]rigin:/d' | sed '/[Xx]-[Rr]untime:/d' |
    sed '/[Xx]-[Pp]ermitted-[Cc]ross-[Dd]omain-[Pp]olicies:/d' | fmt -w 70 -s  | tee -a $HOME/drwho_results/$file.txt
}

#******************* CMS guessing game (by looking for keywords in src-links, response headers & robots.txt)   ***********************
function f_guessCMS {
    if [ ! -f "drwho_tmp/headers.txt" ]; then
        curl -s -I -L --max-time 3 $target > drwho_tmp/headers.txt
    fi
    curl -s -L --max-time 4 $target/robots.txt > drwho_tmp/cms.txt
    curl -s -L --max-time 4 $target > drwho_tmp/target_src.txt
    cat drwho_tmp/headers.txt >> drwho_tmp/cms.txt
    cat drwho_tmp/target_src.txt | grep -w -A 1 "meta" | sed 's/^ *//' >> drwho_tmp/meta.txt
    cat drwho_tmp/headers.txt >> drwho_tmp/cms.txt
    cat drwho_tmp/target_src.txt | grep -w -A 1 "meta" | sed 's/^ *//' >> drwho_tmp/meta.txt
    cat drwho_tmp/target_src.txt | grep -w -A 1 "script=*" >> drwho_tmp/cms.txt
    cat drwho_tmp/target_src.txt | grep -w -A 1 "generator" | sed 's/^ *//' >> drwho_tmp/cms.txt
    cms_type=`cat drwho_tmp/cms.txt | grep -i -o -F -econtao -edrupal -ejoomla -eliferay -etypo3 -ewordpress | tr '[a-z]' '[A-Z]' | sort | uniq`
    echo -e "${B}CMS:${D}  ${cms_type}"
    echo -e "CMS: ${cms_type}" >> $HOME/drwho_results/$file.txt
}

#*************************** website title *********************************
function f_title {
    echo -e "${B}Website Title${D}\n"
    echo -e "\nWebsite Title\n" >> $HOME/drwho_results/$file.txt
    if [ ! -f "drwho_tmp/target_src.txt" ]; then
        curl -s -L --max-time 4 $target > drwho_tmp/target_src.txt
    else
        cat drwho_tmp/target_src.txt | grep -o "<title>[^<]*" | tail -c +8 | fmt -w 90 -s  | tee -a $HOME/drwho_results/$file.txt
    fi
}

#*************************** content of <meta name=description...> tag *********************************
function f_targetDescription {
    echo -e "\n\nDescription\n"  >> $HOME/drwho_results/$file.txt
    cat drwho_tmp/meta.txt | tr -d '"' | tr -d '<' | tr -d '>' | tr -d '/' |sed '/meta name=description content=/!d' |
    sed 's/meta/\nmeta/g' > drwho_tmp/content.txt
    cat drwho_tmp/content.txt | sed '/meta name=description content=/!d' | sed 's/meta name=description content=//' |
    sed 's/&#039;s/s/' | sed 's/link//' | sed 's/meta name=twitter:card//' | sed 's/rel=canonical//' | sed 's/href/\nhref/' |
    sed 's/meta property=og:type//' | sed 's/\!--/\n\!--/' | sed '/\!--/d' | sed '$!N; /^\(.*\)\n\1$/!P; D' | sed 's/^ *//' |
    sed 's/title/\ntitle/' | sed '/name=theme-color/d' | sed '/href=*/d' | sed 's/&amp;/\&/' | fmt -w 70 -s | tee -a $HOME/drwho_results/$file.txt
}


#************************* geolocation data *********************************
function f_geoIP {
    curl -s https://ipapi.co/$address/json | tr -d '{' | tr -d '}' | tr -d ',' | tr -d ' "' | sed -r '/^\s*$/d' |
    fmt -w 70 -s > drwho_tmp/geo.txt
    asn=`cat drwho_tmp/geo.txt | tail -2 | head -1 | cut -d ':' -f 2 | sed 's/^ *//'`
    org=`cat drwho_tmp/geo.txt | tail -1 | cut -d ':' -f 2 | sed 's/^ *//'`
    country=`cat drwho_tmp/geo.txt | grep -w 'country_name' | cut -d ':' -f 2 | sed 's/^ *//'`
    city=`cat drwho_tmp/geo.txt | grep -w 'city' | cut -d ':' -f 2 | sed 's/^ *//'`
    zip=`cat drwho_tmp/geo.txt | grep -w 'postal'  | cut -d ':' -f 2 | sed 's/^ *//'`
    region=`cat drwho_tmp/geo.txt | grep -w 'region' | cut -d ':' -f 2 | sed 's/^ *//'`
    regcode=`cat drwho_tmp/geo.txt | grep -w 'region_code' | cut -d ':' -f 2 | sed 's/^ *//'`
    lat=`cat drwho_tmp/geo.txt | grep -w 'latitude' | cut -d ':' -f 2 | sed 's/^ *//'`
    lon=`cat drwho_tmp/geo.txt | grep -w 'longitude' | cut -d ':' -f 2 | sed 's/^ *//'`
    zone=`cat drwho_tmp/geo.txt | grep -w 'timezone' | cut -d ':' -f 2 | sed 's/^ *//'`
    offset=`cat drwho_tmp/geo.txt | grep -w 'utc_offset' | cut -d ':' -f 2 | sed 's/^ *//'`
    tld=`cat drwho_tmp/geo.txt | grep -w 'country_tld' | cut -d ':' -f 2 | sed 's/^ *//'`
    callcode=`cat drwho_tmp/geo.txt | grep -w 'country_calling_code' | cut -d ':' -f 2 | sed 's/^ *//'`
        echo "ASN:            $asn"                  | tee -a $HOME/drwho_results/$file.txt
        echo "ORG:            $org"                  | tee -a $HOME/drwho_results/$file.txt
        echo ''                                      | tee -a $HOME/drwho_results/$file.txt
        echo "Country:        $country"              | tee -a $HOME/drwho_results/$file.txt
        echo "IDD/ TLD:       $callcode/$tld"        | tee -a $HOME/drwho_results/$file.txt
        echo "TimeZone:       $zone (UTC $offset)"   | tee -a $HOME/drwho_results/$file.txt
        echo ''                                      | tee -a $HOME/drwho_results/$file.txt
        echo "City:           $city"                 | tee -a $HOME/drwho_results/$file.txt
        echo "Region:         $region ($regcode)"    | tee -a $HOME/drwho_results/$file.txt
        echo "Zip-Code:       $zip"                  | tee -a $HOME/drwho_results/$file.txt
        echo "Latitude:       $lat"                  | tee -a $HOME/drwho_results/$file.txt
        echo "Longitude:      $lon"                  | tee -a $HOME/drwho_results/$file.txt
}

#**************************** host whois summary *********************************
function f_whosHost {
    echo -e "${B}Host Whois Summary${D}\n"
    f_textfileSeparator
    echo -e "\n      whois"                  >> $HOME/drwho_results/$file.txt
    echo -e "   ------------\n"         >> $HOME/drwho_results/$file.txt
    echo -e "Host Whois Summary\n"              >> $HOME/drwho_results/$file.txt
    whois $target > drwho_tmp/host-whois.txt
    cat drwho_tmp/host-whois.txt | sed '/^#/d' | sed '/^%/d' | sed '/icann.org/d' | sed '/NOTICE/d' | 
    sed '/reflect/d' | sed '/Fax:/d' |sed '/Fax Ext:/d' | sed '/unsolicited/d' | sed '/HKIRC-Accredited/d' | 
    sed /'how to'/d | sed '/queried/d' | sed '/Bundled/d' | sed '/Registry Domain ID:/d' | sed 's/^ *//' | 
    sed "/^[[:space:]]*$/d"  > drwho_tmp/whois.txt
    grep -w -i -A 1 -m 1 "domain name:" drwho_tmp/whois.txt > drwho_tmp/whois2.txt
    grep -w -i "Domain:" drwho_tmp/whois.txt >> drwho_tmp/whois2.txt
    grep -w -m 1 -A 1 "Registrar:" drwho_tmp/whois.txt >> drwho_tmp/whois2.txt
    grep -w -i -s "Status:" drwho_tmp/whois.txt >> drwho_tmp/whois2.txt
    grep -w -s "Changed:" drwho_tmp/whois.txt >> drwho_tmp/whois2.txt
    grep -w "Company Chinese name:" drwho_tmp/whois.txt >> drwho_tmp/whois2.txt
    grep -w -m 1 "Registrar URL:" drwho_tmp/whois.txt >> drwho_tmp/whois2.txt
    grep -w -m 1 "Registrar Abuse Contact Email:"  drwho_tmp/whois.txt >> drwho_tmp/whois2.txt
    grep -w "Registry Creation Date:" drwho_tmp/whois.txt >> drwho_tmp/whois2.txt
    grep -w -s "Last Modified:" drwho_tmp/whois.txt >> drwho_tmp/whois2.txt
    grep -s -i "Expiry" drwho_tmp/whois.txt >> drwho_tmp/whois2.txt
    grep -w -m 1 "registrar:" drwho_tmp/whois.txt >> drwho_tmp/whois2.txt
    grep -w -m 1 "e-mail:" drwho_tmp/whois.txt >> drwho_tmp/whois2.txt
    grep -w -m 1 "website:" drwho_tmp/whois.txt >> drwho_tmp/whois2.txt
    grep -w -i -A 8 "nic-hdl:" drwho_tmp/whois.txt  >> drwho_tmp/whois2.txt
    echo '' >> drwho_tmp/whois2.txt
    grep -s -w -i -m 1 "Organization:" drwho_tmp/whois.txt >> drwho_tmp/whois2.txt
    grep -s -w -i -m 1 "Registrant Name:" drwho_tmp/whois.txt >> drwho_tmp/whois2.txt
    grep -s -w -i -m 1 "Country:" drwho_tmp/whois.txt >> drwho_tmp/whois2.txt
    grep -s -w -i -m 1 "State/Province" drwho_tmp/whois.txt >> drwho_tmp/whois2.txt
    grep -s -w -i -m 1 "Address:" drwho_tmp/whois.txt >> drwho_tmp/whois2.txt
    grep -s -w -i -m 1 "Registrant Street:" drwho_tmp/whois.txt >> drwho_tmp/whois2.txt
    grep -s -w -i -m 1 "Registrant City:" drwho_tmp/whois.txt >> drwho_tmp/whois2.txt
    grep -s -w -i -m 1 "Registrant Postal Code:" drwho_tmp/whois.txt >> drwho_tmp/whois2.txt
    grep -s -w -i -m 1 "Registrant Phone:" drwho_tmp/whois.txt >> drwho_tmp/whois2.txt
    grep -s -w -i -m 1 "Registrant Email:" drwho_tmp/whois.txt >> drwho_tmp/whois2.txt
    grep -s -w -B 1 -A 16 "ADMINISTRATIVE" drwho_tmp/whois.txt >> drwho_tmp/whois2.txt
    grep -s -w "Registrant:" drwho_tmp/whois.txt >> drwho_tmp/whois2.txt
    grep -s -w -i "Eligibility Type:" drwho_tmp/whois.txt >> drwho_tmp/whois2.txt
    grep -s -w -i "dnssec:" drwho_tmp/whois.txt >> drwho_tmp/whois2.txt
    grep -s -w -i -m 1 "source:" drwho_tmp/whois.txt >> drwho_tmp/whois2.txt
    cat drwho_tmp/whois2.txt | sed '$!N; /^\(.*\)\n\1$/!P; D' | sed 's/nic-hdl:/\nnic-hdl:/' | 
    sed 's/Registrant:/\nRegistrant:/' | sed 's/Administrative/\nAdministrative/' |  
    sed 's/Technical/\nTechnical/' | fmt -w 70 -s | tee -a $HOME/drwho_results/$file.txt
}

#************************** reverse whois summary  *********************************
function f_drwho {
    cat drwho_tmp/rev-whois-lookup.txt | sed '/^#/d' | sed '/^%/d'  | sed '/inject:/d' | sed '/\*/d' | sed '/Parent:/d' |
    sed '/NetType:/d' | sed '/OriginAS:/d' | sed '/tech-c*/d' | sed -r '/^\s*$/d' | sed '/Comment:/d' | sed '/Ref:/d' |
    sed '/ResourceLink:/d' | sed '/OrgAbuseRef:/d'  | sed '/StateProv:/d' | sed '/please/d' | sed "/^[[:space:]]*$/d" |
    fmt -w 60 -s > drwho_tmp/drwho.txt
        grep -s -i -w -m 1 "NetRange" drwho_tmp/drwho.txt > drwho_tmp/drwho2.txt
        grep -s -i -w -m 1 "CIDR" drwho_tmp/drwho.txt >> drwho_tmp/drwho2.txt
        grep -s -i -w -m 1 "NetName" drwho_tmp/drwho.txt >> drwho_tmp/drwho2.txt
        grep -s -i -w -m 1 "NetHandle" drwho_tmp/drwho.txt >> drwho_tmp/drwho2.txt
        grep -s -i -w -m 2 -A 7 "Organization" drwho_tmp/drwho.txt >> drwho_tmp/drwho2.txt
        grep -i -w -m 1 -A 3 "OrgNOCHandle" drwho_tmp/drwho.txt >> drwho_tmp/drwho2.txt
        grep -w -m 1 -A 3 "OrgAbuseHandle:" drwho_tmp/drwho.txt >> drwho_tmp/drwho2.txt
        grep -i -w -m 1 -A 3 "OrgTechHandle" drwho_tmp/drwho.txt >> drwho_tmp/drwho2.txt
        grep -i -w -m 2 -A 4 "inetnum" drwho_tmp/drwho.txt >> drwho_tmp/drwho2.txt
        grep -w -m 1 "admin-c" drwho_tmp/drwho.txt >> drwho_tmp/drwho2.txt
        grep -w -m 1 "mnt-by" drwho_tmp/drwho.txt >> drwho_tmp/drwho2.txt
        grep -w -m 1 "abuse-mailbox" drwho_tmp/drwho.txt >> drwho_tmp/drwho2.txt
        grep -w -m 1 -A 2 "organisation" drwho_tmp/drwho.txt >> drwho_tmp/drwho2.txt
        grep -w -m 1 -A 6 "role" drwho_tmp/drwho.txt >> drwho_tmp/drwho2.txt
        grep -i -w -m 2 -A 5 "person" drwho_tmp/drwho.txt  >> drwho_tmp/drwho2.txt
        grep -w -m 1 "nic-hdl" drwho_tmp/drwho.txt >> drwho_tmp/drwho2.tx
        grep -i -w -m 1 -A 6 "route:" drwho_tmp/drwho.txt >> drwho_tmp/drwho2.txt
    cat drwho_tmp/drwho2.txt | sed '$!N; /^\(.*\)\n\1$/!P; D' |sed 's/inetnum/\ninetnum/' | sed 's/CIDR/\nCIDR/' |
    sed 's/Organization/\nOrganization/' | sed 's/person/\nperson/' | sed 's/OrgAbuseHandle/\nOrgAbuseHandle/' |
    sed 's/OrgNOCHandle/\nOrgNOCHHandle/' | sed 's/OrgTechHandle/\nOrgTechHandle/' | sed 's/role/\nrole/' |
    sed 's/route/\nroute/' | fmt -w 70 -s    | tee -a $HOME/drwho_results/$file.txt
 }

#************************* server response times *********************************
function f_resTime {
  curl $target -s -o /dev/null -w \
  "
  total:           %{time_total}

  connect:         %{time_connect}
  appconnect:      %{time_appconnect}
  start_transfer:  %{time_starttransfer}
  pretransfer:     %{time_pretransfer}

  dns_lookup:      %{time_namelookup}
  redirects:       %{time_redirect}
  "
}

#**************************** optionally run trace path *********************************
function f_tracePath  {
    echo ''
    f_Dashes
    echo -e -n "${B}Run tracepath? [y] yes | no [any key]${D}   "
    read answer
    if [ $answer = "y" ]
        then
        f_Dashes
        echo ''
        f_textfileSeparator 
        echo -e "Tracepath Results \n"             >> $HOME/drwho_results/$file.txt
        tracepath -b -m 22 $target                 | tee -a $HOME/drwho_results/$file.txt
    else
        f_Dashes
    fi
}

#*************************** use lynx to scrape target website for hyperlinks *********************************
function f_linkDump {
   f_textfileSeparator
    echo -e "       Link Dump"                 >> $HOME/drwho_results/$file.txt
    echo -e "    ----------------\n"           >> $HOME/drwho_results/$file.txt
    echo -e "${B}Link Dump${D}\n"
    if ! type lynx &> /dev/null; then
        echo "Please install lynx"
    else
        lynx -accept_all_cookies -dump -listonly www.$target
    fi
echo ''
}

#**************************** searches for hosts in assumed /24 block via reverse dns lookup *********************************
function f_hostSearch {

    for i in `seq 1 255` ; do sublist="$sublist ${prefx}.$i" ; done
    for i in $sublist ; do
        ptr=`host $i | cut -d ' ' -f 5`
        echo "$i - $ptr" | sed '/NXDOMAIN/d'
    done
}

#**************************** checking if server allows unauthorized zone transfers  *********************************
function f_zoneTransfer {
    dig ns +short $target | rev | cut -c  2- | rev > drwho_tmp/ns.txt
    for i in $(cat drwho_tmp/ns.txt); do
        dig axfr @${i} $target
    done
}

#**************************** banner for output text file *********************************
function f_textfileBanner {
    echo -e "   ------------"                >> $HOME/drwho_results/$file.txt
    echo -e "      Drwho"                    >> $HOME/drwho_results/$file.txt
    echo -e "   ------------"                >> $HOME/drwho_results/$file.txt
    echo -e "\nAuthor - Thomas Wy, June 2020\n"   >> $HOME/drwho_results/$file.txt
    echo -e "Target:  $target"                  >> $HOME/drwho_results/$file.txt
    date                                        >> $HOME/drwho_results/$file.txt

}

#******************** startmenu with global options  *********************************
function f_startMenu {
    echo "   1)  SET TARGET DOMAIN"
    echo "   2)  SET TARGET IP"
    echo "   3)  DOMAIN OPTIONS"
    echo "   4)  IP OPTIONS"
    echo "   5)  ASN QUERY (ext. API)"
    echo "   0)  QUIT"
}

#******************** submenu IP - related options  **************************************
function f_menuIP {
    f_solidLong
    echo -e "${B}  >>  Target: $target${D}\n"
    echo ''
    echo -e "  ${W}31)${B}   dns & whois reverse lookup"
    echo -e "  ${W}32)${B}   target geolocation (ext. API)"
    echo -e "  ${W}33)${B}   HTTP headers summary,PTR & website title"
    echo -e "  ${W}34)${B}   server response times & tracepath"
    echo -e "  ${W}35)${B}   server certificates"
    echo -e "  ${W}36)${B}   dump HTTP headers"
    echo -e "  ${W}37)${B}   link dump"
    echo -e "  ${W}38)${B}   address block reverse host search"
    echo -e "  ${W}39)${B}   reverse IP lookup (ext. API)"
    f_solidShort
}


function f_menuDomain {
f_solidLong
echo -e "${B}  >>  Target: $target - $host_ip${D}\n"
    echo ''
    echo -e "  ${W}11)${B}   Website Overview\n        (Status, Headers Summary, Host IP, CMS, Title &  Content Tags, Social Media Links)"
    echo -e "  ${W}12)${B}   A,AAAA,MX,NS,PTR,SOA & TXT records"
    echo -e "  ${W}13)${B}   certificate information & -files"
    echo -e "  ${W}14)${B}   whois lookup options"
    echo -e "  ${W}15)${B}   geolocation options (ext.API)"
    echo -e "  ${W}16)${B}   server response times & tracepath"
    echo -e "  ${W}17)${B}   get HTTP headers / robots.txt / hyperlinks"
    echo -e "  ${W}18)${B}   zone transfer check"
    echo -e "  ${W}19)${B}   address block reverse host search"
    echo -e "  ${W}20)${B}   subdomain enumeration (ext.API)"
    echo -e "  ${W}21)${B}   reverse IP lookup (ext.API)"
f_solidShort
}

#******************** submenu IP - whois & IP geolocation options  **************************************
function f_whoisOptions {
    echo -e "      ${B}Reverse Whois Lookup Options\n"
    echo -e "  41)  $target whois & reverse whois summary"
    echo -e "  42)  MX reverse whois summary"
    echo -e "  43)  SOA reverse  whois summary"
    f_solidShort
}

function f_geoOptions {
    echo -e "      ${B}Geolocation Options\n"
    echo -e "  51)  $target geolocation"
    echo -e "  52)  MX record geolocation"
    echo -e "  53)  SOA record geolocation"
    f_solidShort
}

function f_optionsFiledump {

    echo -e "      ${B}Dump Stuff\n"
    echo -e "  61)  HTTP headers"
    echo -e "  62)  robots.txt"
    echo -e "  63)  linkdump"
    f_solidShort
}


#******************** main program loop **************************************
while true
do
f_startMenu
echo ''
echo -e -n "   ${B}?${D}  "
read choice
case $choice in
1)
#************** SET TARGET DOMAIN / IP  ********************
f_solidLong
f_makePermDir
echo -e "  Set Target ${B}DOMAIN${D} - e.g. example.com\n"
echo -e -n "  ${B}>>${D}  "
read target
echo -e "\nResults will be stored inside \"drwho_results\" in your home folder.\n "
echo -e "Please enter a file name:\n "
echo -e -n "  ${B}>>${D}  "
read file
host_ip=`echo | host -t A $target | head -1 | cut -d " " -f 4`
f_textfileSeparator
f_textfileBanner
f_menuDomain
;;
2)
f_solidLong
f_makePermDir
echo -e "   Set Target ${B}IP${D} - e.g. 45.33.32.156\n"
echo -e -n "  ${B}>>${D}  "
read target
echo -e "\nResults will be stored inside \"drwho_results\" in your home folder.\n "
echo -e "Please enter a file name:\n "
echo -e -n "  ${B}>>${D}  "
read file
f_textfileSeparator
f_textfileBanner
f_menuIP
;;
3)
#************** 3), 4) SUBMENUS For DOMAIN & IP  OPTIONS ********************
f_menuDomain
;;
4)
f_menuIP
;;
5)
#************** 5) AS Information ********************
f_solidLong
echo -e "   Set Target ${B}AS${D} - e.g. AS8068 - or ${B}IP${D}\n"
echo -e -n "  ${B}>>${D}  "
read target_as
echo -e "\nResults will be stored inside \"drwho_results\" in your home folder.\n "
echo -e "Please enter a file name:\n "
echo -e -n "  ${B}>>${D}  "
read file
f_solidLong
echo -e "${B}Autonomous System Information (ext.API)${D}\n\n"
f_textfileSeparator
echo -e "      AS Information"      >> $HOME/drwho_results/$file.txt
echo -e "   ----------------------\n" >> $HOME/drwho_results/$file.txt
echo -e "Target:  $target_as\n\n" >> $HOME/drwho_results/$file.txt
curl -s curl https://api.hackertarget.com/aslookup/?q=$target_as | tee -a $HOME/drwho_results/$file.txt
echo ''
f_solidLong
;;
11)
f_solidLong
f_makeNewDir
f_textfileSeparator
#check host availability / network connection
error_code=6
curl -sf "${target}" > /dev/null
if [ $? = ${error_code} ];then
echo -e "${R} CONNECTION: FAILURE${D}\n"
echo -e " CONNECTION: FAILURE${D}" >> $HOME/drwho_results/$file.txt
continue
else
echo -e "${B}Server Status:  ${GR}ONLINE${D}"
echo -e " \nSERVER STATUS: ONLINE\n\n" >> $HOME/drwho_results/$file.txt
fi
echo -e "\n"
f_headers
#******** CMS, host IP addresses, website title & -description, social media links ********
echo -e "\n\nHost IP Addresses\n" >> $HOME/drwho_results/$file.txt
echo -e "\n${B}Host IP Addresses${D}\n"
host -t A $target | cut -d ' ' -f 4- | tee -a $HOME/drwho_results/$file.txt
echo -e "${G}---------------\033[0m"
echo -e "---------------" >> $HOME/drwho_results/$file.txt
host -t AAAA $target | cut -d ' ' -f 3- | tee -a $HOME/drwho_results/$file.txt
echo -e "\n"
f_textfileSeparator
f_guessCMS
echo -e ''
f_title
echo -e "\n\n${B}Description${D}\n"
f_targetDescription
f_solidLong
echo -e "${B}Social Media & Contact Links ${D}\n"
f_textfileSeparator
echo -e "Social Media & Contact Links \n" >> $HOME/drwho_results/$file.txt
lynx -accept_all_cookies -dump -listonly -nonumbers www.$target | grep -F -econtact -ediscord -ekontakt -econtatto -eimpressum -eetsy -efacebook -egithub -einstagram -elinkedin -epinterest -ereddit -etwitter -exing -eyoutube | sed '/sport/d' |  sed '/program/d'  | sort | uniq | fmt -w 60 -s | tee -a $HOME/drwho_results/$file.txt
f_removeDir
f_solidLong
;;
12)
#********** 12) DNS Records - A, AAAA, MX, NS, PTR, SOA, TXT **********
f_solidLong
f_textfileSeparator
echo -e "      DNS Records"          >> $HOME/drwho_results/$file.txt
echo -e "   ------------------\n"    >> $HOME/drwho_results/$file.txt
dig a  +noall +answer  +nottlid $target     >> $HOME/drwho_results/$file.txt
dig aaaa +noall +answer  +nottlid $target   >> $HOME/drwho_results/$file.txt
echo ''                                     >> $HOME/drwho_results/$file.txt
dig mx  +noall +answer  +nottlid $target    >> $HOME/drwho_results/$file.txt
echo ''                                     >> $HOME/drwho_results/$file.txt
dig ns  +noall +answer  +nottlid $target    >> $HOME/drwho_results/$file.txt
echo -e "${B}$target A & AAAA Records${D}\n"
host -t A $target | cut -d ' ' -f 4-
echo -e "${G}---------------\033[0m"
host -t AAAA $target | cut -d ' ' -f 3-
echo -e "\n\n${B}$host_ip PTR Record${D}\n"
echo -e "\n\nPTR Record\n"                  >> $HOME/drwho_results/$file.txt
host -t A $host_ip | cut -d ' ' -f 3- | rev | cut -d '.' -f 2- | rev  | tee -a $HOME/drwho_results/$file.txt
echo -e "\n\n${B}MX Priorities${D}\n"
dig mx +short $target
echo -e "\n\n${B}SOA Record${D}\n"
echo -e "\n\nSOA Record\n"                   >> $HOME/drwho_results/$file.txt
dig soa +short $target               | tee -a $HOME/drwho_results/$file.txt
f_solidLong
mx_url=`dig mx +short $target | rev | cut -c 2- | rev | cut -d " " -f 2-`
ns_url=`dig ns +short $target | rev | cut -c 2- | rev`
f_textfileSeparator
echo -e "      MX, NS  A & AAAA Records"       >> $HOME/drwho_results/$file.txt
echo -e "   -------------------------------\n" >> $HOME/drwho_results/$file.txt
f_ipv4                              | tee -a $HOME/drwho_results/$file.txt
f_solidLong
f_ipv6                              | tee -a $HOME/drwho_results/$file.txt
f_solidLong
echo -e "${B}TXT Record(s)${D}\n "
f_textfileSeparator
echo -e "TXT Record\n"              >> $HOME/drwho_results/$file.txt
txt=`dig txt +short $target`
echo "$txt" | fmt -s -w 70          | tee -a $HOME/drwho_results/$file.txt
f_solidLong
;;
13)
#*********************** 13) server certificates **************************
f_solidLong
f_makeNewDir
f_certInfo
echo ''
f_Dashes_long
echo -e -n "${B}Display certificates & public key? yes [y] | no [any key]${D}   "
read answer
if [ $answer = "y" ]
then
f_Dashes_long
echo ''
f_textfileSeparator
f_showCerts | tee -a $HOME/drwho_results/$file.txt
fi
f_removeDir
f_solidLong
;;
14)
#************** 14) whois options ********************
f_solidLong
f_whoisOptions
;;
41)
#***********************  41) host whois & rev. whois summary  **************************
f_solidLong
f_makeNewDir
f_whosHost
f_solidLong
f_textfileSeparator
whois $host_ip > drwho_tmp/rev-whois-lookup.txt
echo -e "${B}Host Reverse Whois Summary${D}\n"
echo -e "\n     Host Reverse whois Summary"  >> $HOME/drwho_results/$file.txt
echo -e "   ---------------------------------\n"        >> $HOME/drwho_results/$file.txt
echo -e " ${BDim}$target - $host_ip${D}\n"
f_drwho
f_removeDir
f_solidLong
;;
42)
#******************* 42) mx- record reverse whois" **********************
f_solidLong
f_makeNewDir
mx_url=`dig mx +short $target | rev | cut -c 2- | rev | cut -d " " -f 2-`
mx_first_url=`echo "$mx_url" | sort | head -1`
mx_first_ip=`host -t A $mx_first_url | cut -d ' ' -f 4- | sort | head -1`
whois $mx_first_ip > drwho_tmp/rev-whois-lookup.txt
echo -e "${B}MX Record Reverse whois Summary${D}\n"
echo -e " ${BDim}$mx_first_url - $mx_first_ip${D}\n"
f_textfileSeparator
echo -e "\n      MX reverse whois"              >> $HOME/drwho_results/$file.txt
echo -e "   -----------------------\n"        >> $HOME/drwho_results/$file.txt
echo -e "MX Record Reverse whois Summary\n"   >> $HOME/drwho_results/$file.txt
echo -e " $mx_first_url - $mx_first_ip\n"     >> $HOME/drwho_results/$file.txt
f_drwho
echo -e "\n${BDim}The results shown are for the \nMX record that comes first in either \npriority or alphabetical order${D}" |
tee -a $HOME/drwho_results/$file.txt
f_removeDir
f_solidLong
f_whoisOptions
;;
43)
#******************* 43) soa- record reverse whois" **********************
f_solidLong
f_makeNewDir
soa_url=`dig soa +short $target | cut -d ' ' -f 1 | rev | cut -c 2- | rev`
soa_ip=`host -t A $soa_url | cut -d ' ' -f 4-`
whois $soa_ip > drwho_tmp/rev-whois-lookup.txt
echo -e "${B}SOA Record Reverse whois Summary\n"
echo -e " ${BDim}$soa_url - $soa_ip${D}\n"
f_textfileSeparator
echo -e "\n      SOA reverse whois"             >> $HOME/drwho_results/$file.txt
echo -e "   -------------------------\n"        >> $HOME/drwho_results/$file.txt
f_drwho
f_removeDir
f_solidLong
f_whoisOptions
;;
15)
#************** 15) ip geolocation options ********************
f_solidLong
f_geoOptions
;;
51)
#*******************  51) host geolocation via ip-api.co  **********************
f_solidLong
f_makeNewDir
echo -e "${B}Host IP Geolocation${D}\n"
echo -e " ${BDim}$target - $host_ip${D}"
f_textfileSeparator
echo -e "\n      Host Geolocation"        >> $HOME/drwho_results/$file.txt
echo -e "   -----------------------\n"  >> $HOME/drwho_results/$file.txt
address=`echo $host_ip`
echo ''
f_geoIP
f_removeDir
f_solidLong
f_geoOptions
;;
52)
#******************* 52) geolocation data for "first" MX record (first in either priority or alphabetical order) **********************
f_solidLong
f_makeNewDir
mx_url=`dig mx +short $target | rev | cut -c 2- | rev | cut -d " " -f 2-`
mx_first_url=`echo "$mx_url" | sort | head -1`
mx_first_ip=`host -t A $mx_first_url | cut -d ' ' -f 4- | sort | head -1`
whois $mx_first_ip > drwho_tmp/rev-whois-lookup.txt
echo -e "${B}MX Record Geolocation\n"
echo -e " ${BDim}$mx_first_url - $mx_first_ip${D}\n"
f_textfileSeparator
echo -e "\n      MX Geolocation"         >> $HOME/drwho_results/$file.txt
echo -e "   ---------------------\n"    >> $HOME/drwho_results/$file.txt
address=`echo $mx_first_ip`
f_geoIP
echo -e "\n${BDim}The results shown above are for the \nMX record that comes first in either \npriority or alphabetical order${D}" |
tee -a $HOME/drwho_results/$file.txt
f_removeDir
f_solidLong
f_geoOptions
;;
53)
#******************* 53) geolocation data for SOA record **********************
f_solidLong
f_makeNewDir
echo -e "${B}SOA Record Geolocation${D}\n"
soa_url=`dig soa +short $target | cut -d ' ' -f 1 | rev | cut -c 2- | rev`
soa_ip=`host -t A $soa_url | cut -d ' ' -f 4-`
echo -e " ${BDim}$soa_url - $soa_ip${D}\n"
f_textfileSeparator
echo -e "\n      SOA Geolocation"        >> $HOME/drwho_results/$file.txt
echo -e "   ----------------------\n"    >> $HOME/drwho_results/$file.txt
address=`echo $soa_ip`
f_geoIP
f_removeDir
f_solidLong
;;
16)
#************** 15) server response times ********************
f_solidLong
f_textfileSeparator
echo -e "${B}Server Response Times${D}"
echo -e "      Server Response Times"          >> $HOME/drwho_results/$file.txt
echo -e "   ----------------------------\n"     >> $HOME/drwho_results/$file.txt
error_code=6
curl -sf "${target}" > /dev/null
 if [ $? = ${error_code} ];then
echo -e " ${R}CONNECTION: FAILURE ${D}\n" | tee -a $HOME/drwho_results/$file.txt
continue
else
echo -e "${B}$target Status:  ${GR}ONLINE${D}"
echo -e " \nSERVER STATUS: ONLINE\n\n"          >> $HOME/drwho_results/$file.txt
fi
echo -e "${BDim}$target - $host_ip${D}"
echo -e "$target - $host_ip"                    >> $HOME/drwho_results/$file.txt
f_resTime                                 | tee -a $HOME/drwho_results/$file.txt
f_tracePath
f_solidLong
;;
17)
#************** 15) file dump options ********************
f_solidLong
f_optionsFiledump
;;
61)
#************** 61) dump HTTP - headers ********************
f_solidLong
echo -e "${B}HTTP Headers${D}\n"
f_textfileSeparator
echo -e "\n      HTTP-Headers"        >> $HOME/drwho_results/$file.txt
echo -e "   ------------------\n"   >> $HOME/drwho_results/$file.txt
curl -s -I -L --max-time 4 $target  | tee -a $HOME/drwho_results/$file.txt
f_solidLong
;;
62)
#************** 62) dump robots.txt - File ********************
f_solidLong
echo -e "${B}robots.txt${D}\n"
f_textfileSeparator
echo -e "      robots.txt"           >> $HOME/drwho_results/$file.txt
echo -e "   -----------------\n"     >> $HOME/drwho_results/$file.txt
echo -e "$targetrobots.txt File\n"  >> $HOME/drwho_results/$file.txt
curl -s -L $target/robots.txt        | tee -a $HOME/drwho_results/$file.txt
echo ''
f_solidLong
;;
63)
#************** 63) link dump *****************
f_solidLong
f_linkDump | tee -a $HOME/drwho_results/$file.txt
echo ''
f_solidLong
;;
18)
#*******************  18) check if unauthorized zone transfers are permitted **********************
f_solidLong
f_makeNewDir
echo -e "${B}Zone Transfer Check${D}\n "
f_textfileSeparator
echo -e "\n      Zone Transfer Check"         >> $HOME/drwho_results/$file.txt
echo -e "   ---------------------------\n"  >> $HOME/drwho_results/$file.txt
f_zoneTransfer                              | tee -a $HOME/drwho_results/$file.txt
f_removeDir
f_solidLong
;;
19)
#*******************  19) address block reverse host search **********************
f_solidLong
echo -e "${B}Address Block Reverse Host Search${D}\n\n"
f_textfileSeparator
echo -e "\n      Reverse Host Search"           >> $HOME/drwho_results/$file.txt
echo -e "   ---------------------------\n"    >> $HOME/drwho_results/$file.txt
prefx=`dig x +short $target | rev | cut -d '.' -f 2- | rev`
f_hostSearch | tee -a  $HOME/drwho_results/$file.txt
f_solidLong
;;
20)
#*******************  20) subdomain enumeration via hackertarget.com - API **********************
f_solidLong
echo -e "${B}$target Subdomains${D}\n\n"
f_textfileSeparator
echo -e "\n      Subdomains"            >> $HOME/drwho_results/$file.txt
echo -e "   -----------------\n"      >> $HOME/drwho_results/$file.txt
echo -e "$target Subdomains\n\n"      >> $HOME/drwho_results/$file.txt
curl -s https://api.hackertarget.com/hostsearch/?q=$target | sed 's/,/ -  /g'  | tee -a $HOME/drwho_results/$file.txt
echo -e "\n"
f_solidLong
;;
21)
#*******************  21) reverse IP lookup via hackertarget.com - API **********************
f_solidLong
echo -e "${B}Reverse IP Lookup${D}\n"
echo -e " ${BDim} $target - $host_ip${D}\n"
f_textfileSeparator
echo -e "\n      Reverse IP Lookup"      >> $HOME/drwho_results/$file.txt
echo -e "   ------------------------\n" >> $HOME/drwho_results/$file.txt
echo -e "\n$target - $host_ip\n"        >> $HOME/drwho_results/$file.txt
curl -s https://api.hackertarget.com/reverseiplookup/?q=$host_ip | tee -a $HOME/drwho_results/$file.txt
echo -e "\n"
f_solidLong
;;
31)
#******************* 31) target - dns & whois reverse lookup   **********************
f_solidLong
f_makeNewDir
f_textfileSeparator
echo -e "\n      whois"              >> $HOME/drwho_results/$file.txt
echo -e "   -----------\n"         >> $HOME/drwho_results/$file.txt
echo -e "$target PTR Record\n" >> $HOME/drwho_results/$file.txt
echo -e "${B}$target PTR Record${D}\n"
host -t A $target | cut -d ' ' -f 3- | rev | cut -d '.' -f 2- | rev | tee -a $HOME/drwho_results/$file.txt
echo -e "\n"  >> $HOME/drwho_results/$file.txt
whois $target > drwho_tmp/rev-whois-lookup.txt
echo -e "\n\n${B}$target Reverse Whois Summary${D}\n"
f_drwho
f_removeDir
f_solidLong
;;
32)
#******************* 32) target geolocation via ip-api.co  **********************
f_solidLong
f_makeNewDir
echo -e "${B}IP Geolocation${D}\n"
f_textfileSeparator
echo -e "      IP Geolocation"         >> $HOME/drwho_results/$file.txt
echo -e "   ----------------------\n"  >> $HOME/drwho_results/$file.txt
echo -e "\n$target Geolocation"        >> $HOME/drwho_results/$file.txt
address=`echo $target`
echo ''
f_geoIP
echo ''
f_removeDir
f_solidLong
;;
33)
#******************* 33) headers summary, PTR & website title  **********************
f_solidLong
f_textfileSeparator
echo -e "\n      HEADERS Summary & TITLE"        >> $HOME/drwho_results/$file.txt
echo -e "   ------------------------------\n"   >> $HOME/drwho_results/$file.txt
f_makeNewDir
error_code=6
curl -sf "${target}" > /dev/null
if [ $? = ${error_code} ];then
echo -e "${R} CONNECTION: FAILURE${D}\n"  | tee -a $HOME/drwho_results/$file.txt
continue
else
echo -e "${B}Server Status:  ${GR}ONLINE${D}"
echo -e " \nSERVER STATUS: ONLINE\n\n"          >> $HOME/drwho_results/$file.txt
fi
echo -e "\n"
f_headers
f_solidLong
f_textfileSeparator
echo -e "\n${B}$target PTR Record${D}\n"
echo -e "\n\n$target PTR Record\n" >> $HOME/drwho_results/$file.txt
host -t A $target | cut -d ' ' -f 3- | rev | cut -d '.' -f 2- | rev | tee -a $HOME/drwho_results/$file.txt
echo '' | tee -a $HOME/drwho_results/$file.txt
f_title
f_solidLong
f_removeDir
;;
34)
#******************* 34) server status, response times & tracepath  **********************
f_solidLong
f_textfileSeparator
echo -e "      Server Response Times"         >> $HOME/drwho_results/$file.txt
echo -e "   ----------------------------\n"   >> $HOME/drwho_results/$file.txt
error_code=6
curl -sf "${target}" > /dev/null
 if [ $? = ${error_code} ];then
echo -e " ${R}CONNECTION: FAILURE ${D}\n" | tee -a $HOME/drwho_results/$file.txt
continue
else
echo -e "${B}$target Status:  ${GR}ONLINE${D}"
echo -e " \nSERVER STATUS: ONLINE\n\n"          >> $HOME/drwho_results/$file.txt
fi
echo -e "${B}Server Response Times${D}\n"
f_resTime | tee -a $HOME/drwho_results/$file.txt
f_tracePath
f_solidLong
;;
35)
#***********************  35) server certificates **************************
f_solidLong
f_makeNewDir
f_certInfo
f_solidLong
f_textfileSeparator
echo ''
f_Dashes_long
echo -e -n "${B}Display certificates & public key? yes [y] | no [any key]${D}   "
read answer
if [ $answer = "y" ]
then
f_Dashes_long
echo ''
f_showCerts | tee -a $HOME/drwho_results/$file.txt
fi
f_solidLong
f_removeDir
;;
36)
#***********************  36) dump HTTP - headers **************************
f_solidLong
echo -e "${B}HTTP Headers${D}\n"
f_textfileSeparator
echo -e "\n      HTTP-Headers"        >> $HOME/drwho_results/$file.txt
echo -e "   -----------------\n"    >> $HOME/drwho_results/$file.txt
echo -e "$target HTTP-Headers \n"   >> $HOME/drwho_results/$file.txt
curl -s -I -L --max-time 4 $target  | tee -a $HOME/drwho_results/$file.txt
echo ''
f_solidLong
;;
37)
#***********************  37) link dump **************************
f_solidLong
f_linkDump
f_solidLong
;;
38)
#*******************  38) address block reverse host search **********************
f_solidLong
echo -e "${B}Address Block Reverse Host Search${D}\n\n"
f_textfileSeparator
echo -e "\n      Reverse Host Search"        >> $HOME/drwho_results/$file.txt
echo -e "   --------------------------\n"   >> $HOME/drwho_results/$file.txt
echo -e "Address Block Reverse Host Search\n\n" >>  $HOME/drwho_results/$file.txt
prefx=`echo $target | rev | cut -d '.' -f 2- | rev`
f_hostSearch  | tee -a  $HOME/drwho_results/$file.txt
f_solidLong
;;
39)
#******************* 39) reverse IP lookup via hackertarget.com - API **********************
f_solidLong
echo -e "${B}Reverse IP Lookup${D}\n"
echo -e " ${BDim}Target: $target${D}\n\n"
f_textfileSeparator
echo -e "\n      Reverse IP Lookup"        >> $HOME/drwho_results/$file.txt
echo -e "   ------------------------\n"  >> $HOME/drwho_results/$file.txt
echo -e "\nTarget:  $target\n"           >> $HOME/drwho_results/$file.txt
curl -s https://api.hackertarget.com/reverseiplookup/?q=$target | tee -a $HOME/drwho_results/$file.txt
echo -e "\n"
f_solidLong
;;
#******************* 9) exit  **********************
0)
echo -e "\n\n" >> $HOME/drwho_results/$file.txt
f_removeDir
echo -e "\n${B}----------------------------- Done ------------------------------\n"
echo -e "                  ${BDim}Author - Thomas Wy, June 2020${D}\n\n"
break
;;
esac
done


























































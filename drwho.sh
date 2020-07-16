#!/bin/bash
#************** Variables - colors ***************
B='\033[1;34m'
BDim='\033[0;34m'
D='\033[0m'
GREY='\033[1;30m'
GR='\033[1;32m'
R='\033[1;31m'

#************** Variables - directories ***************

tempdir="$PWD/drwho_temp"
permdir="$PWD/drwho_results"

#************** drwho - banner *************

echo -e "${B}\n
 ____                _           
|  _ \ _ ____      _| |__   ___  
| | | | '__\ \ /\ / / '_ \ / _ \ 
| |_| | |   \ V  V /| | | | (_) |
|____/|_|    \_/\_/ |_| |_|\___/ 

${D}"

#**************** Functions ***************

#************ create temporary working directory *************
function f_makeNewDir {

if [ -d $tempdir ]; then
rm -rf $tempdir
fi
mkdir $tempdir
}

#************ delete temporary working directory *************
function f_removeDir {
if [ -d $tempdir ]; then
rm -rf $tempdir
fi
}

#************ directory containing the output text file*************
function f_makePermDir {
if [ ! -d $permdir ]; then
mkdir $permdir
fi
}

#*********** banner for output file *************
function f_textfileBanner {
    echo -e "    ------------"                      >> $permdir/$file.txt
    echo -e "       Drwho"                          >> $permdir/$file.txt
    echo -e "    ------------"                      >> $permdir/$file.txt
    echo -e "\nAuthor - Thomas Wy, July 2020\n"     >> $permdir/$file.txt
    echo -e "https://github.com/ThomasPWy/drwho.sh \n" >> $permdir/$file.txt
    echo -e "TARGET:  $target"                      >> $permdir/$file.txt
    date                                            >> $permdir/$file.txt

}

#************ separators (solid, dashed) *************
function f_solidLong {
    echo -e "\n${GREY}________________________________________________________________________${D}\n"
}

#************ short horizontal line *************
function f_solidShort {
    echo -e "${BDim}      ____${D}\n"
}

function f_Dashes {
     echo -e "${BDim}------------------------------------------${D}"
}

function f_Dashes_long {
     echo -e "${BDim}--------------------------------------------------------------------${D}"
}

function f_textfileSeparator {
echo -e "\n______________________________________________________________________________\n" >> $permdir/$file.txt
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
    echo -e "\n=== NS AAAA Records ===\n"
            for i in $(echo $ns_url)
            do
                echo |  host -t AAAA $i | sed -e s/'has'/'\n'/ | sed s/IPv6// | sed s/address//
                echo ''
            done
}

#************ certificate status & algorithms *************
function f_certInfo {
timeout 3 openssl s_client -connect $target:443 -brief 2>$tempdir/ssl_sum2.txt
echo | timeout 3 openssl s_client -connect $target:443 2>$tempdir/status.txt -status >> $tempdir/status.txt
echo | timeout 3 openssl s_client -connect $target:443 2>>$tempdir/ssl_sum2.txt | openssl x509 -text -enddate >> $tempdir/ssl_sum2.txt
cat $tempdir/ssl_sum2.txt | tr -d '"' | sed 's/ = /: /g' | sed 's/_/ - /g' | tr -d '(' | tr -d ')' |
sed 's/^ *//' > $tempdir/ssl.txt
#*** subject ***
subject=`cat $tempdir/ssl.txt | grep -m 1 -w 'Subject:' | sed 's/, Inc/ Inc/' | sed 's/,/\n/g' | sed 's/Subject://g'`
subject_org=`echo "$subject" | grep -w 'O:' | sed 's/^ *//' | sed 's/O:/Org: /'`
subject_location=`echo "$subject" | grep -w 'L:' | tr -d ' '  | sed 's/L:/\/ /' | sed 's/^ *//'`
subject_country=`echo "$subject" | grep -w 'C:' | tr -d ' ' | sed 's/C:/\/ /'  `
subject_cn=`echo "$subject" | grep -w 'CN:' | sed 's/^ *//' | sed 's/CN:/CN:  /'`
#*** issuer ***
issuer=`cat $tempdir/ssl.txt | grep -m 1 -w 'Issuer:' | sed 's/, Inc//' | sed 's/,/\n/g'| sed 's/Issuer://g'`
issuer_org=`echo "$issuer" | grep -w 'O:' | sed 's/^ *//' | sed 's/O:/Org: /'`
issuer_location=`echo "$issuer" | grep -w 'L:' | tr -d ' '  | sed 's/L:/\/ /' | sed 's/^ *//'`
issuer_country=`echo "$issuer" | grep -w 'C:' | tr -d ' ' | sed 's/C:/\/ /'`
issuer_cn=`echo "$issuer" | grep -w 'CN:' | sed 's/^ *//' | sed 's/CN:/CN:  /'`
#*** algos *** 
cipher=`cat $tempdir/ssl.txt | grep -i -m 1 'ciphersuite' | cut -d ':' -f 2-`
protocol=`cat $tempdir/ssl.txt | grep -i -m 1 'protocol' | cut -d ':' -f 2-`
algo=`cat $tempdir/ssl.txt | grep -i -m 1 'algorithm' | sed s/'With'/' with '/g  | sed s/'Encryption'/' Encryption'/g | 
cut -d ':' -f 2-`
key_algo=`cat $tempdir/ssl.txt | grep -i -m 1 -A 2 'public' | sed '/Info/d' |  sed '/Algorithm:/d'  | 
sed 's/Public-Key//' | sed 's/ : /, /' | sed 's/^ *//g'`
echo -e -n "Expires:    "
cat $tempdir/ssl.txt | grep -i -m 1 'after' | cut -d ' ' -f 4-
echo -e  "\nSubject:    $subject_cn"
echo -e  "\nIssuer:     $issuer_cn"
echo -e "\n\nTLS-Vers.: $protocol"
echo -e "\nCipher:    $cipher"
echo -e "\nSignature: $algo"
echo -e "\nPublicKey:  $key_algo"
#*** certificate chain ***
echo -e "\n\n\n=== Certificate Chain (depth:2-1-0) === \n\n"
#*** root ca ***
root_ca=`cat $tempdir/ssl.txt | grep -i -m 1 -A 1 'depth=2' | sed 's/depth=2//' | sed 's/,/\n/g' | sed '/postal/d' |
sed '/street:/d' | sed 's/^ *//' | sed 's/verify/\nverify/' | sed 's/return:/return: /'`
root_ca_org=`echo "$root_ca" | grep -w 'O:' | sed 's/^ *//' | sed 's/O:/Org: /'`
root_ca_country=`echo "$root_ca" | grep -w 'C:' | tr -d ' ' | sed 's/C:/\/ /' | sed 's/^ *//'`
root_ca_location=`echo "$root_ca" | grep -w 'L:' | tr -d ' '  | sed 's/L:/\/ /' | sed 's/^ *//'`
root_ca_cn=`echo "$root_ca" | grep -w 'CN:' | sed 's/^ *//' | sed 's/CN:/CN:  /'`
#*** issuer of leaf certificate ***
ca=`cat $tempdir/ssl.txt | grep -i -m 1 -A 1 'depth=1' | sed 's/depth=1//' | sed 's/,/\n/g'`
ca_org=`echo "$ca" | grep -w 'O:' | sed 's/^ *//' | sed 's/O:/Org: /'`
ca_country=`echo "$ca" | grep -w 'C:' | tr -d ' ' | sed 's/C:/\/ /' | sed 's/^ *//'`
ca_location=`echo "$ca" | grep -w 'L:' | tr -d ' '  | sed 's/L:/\/ /' | sed 's/^ *//'`
ca_cn=`echo "$ca" | grep -w 'CN:' | sed 's/^ *//' | sed 's/CN:/CN:  /'`
#*** output ***
echo -e "\nRootCA:     $root_ca_cn"
echo "            $root_ca_org $root_location $root_ca_country"
echo "$root_ca" | grep -i -w 'verify' | sed 's/return://' | sed 's/verify/                  verify/'
echo -e "\nIssuer:     $ca_cn"
echo "            $ca_org $ca_location $ca_country"
echo "$ca" | grep -i -w 'verify' | sed 's/return://' | sed 's/verify/                  verify/'
echo -e  "\nSubject:    $subject_cn"
echo "            $subject_org $subject_location $subject_country"
cat $tempdir/ssl.txt | grep -i -w -m 1 -A 1 'Constraints:' | sed "/constraints:/d" | sed "/Constraints:/d" | sed 's/CA:/            CA:   /'
}

function f_certQuick {
timeout 3 openssl s_client -connect $target:443 -brief 2>$tempdir/ssl_sum2.txt
echo | timeout 3 openssl s_client -connect $target:443 2> $tempdir/status.txt -status >> $tempdir/status.txt
echo | timeout 3 openssl s_client -connect $target:443 2>>$tempdir/ssl_sum2.txt | openssl x509 -text -enddate >> $tempdir/ssl_sum2.txt
cat $tempdir/ssl_sum2.txt | tr -d '"' | sed 's/ = /: /g' | sed 's/_/ - /g' | tr -d '(' | tr -d ')' |
sed 's/^ *//' > $tempdir/ssl.txt
#*** subject ***
subject=`cat $tempdir/ssl.txt | grep -m 1 -w 'Subject:' | sed 's/, Inc/ Inc/' | sed 's/,/\n/g' | sed 's/Subject://g'`
subject_country=`echo "$subject" | grep -w 'C:' | tr -d ' ' | sed 's/C:/\/ /'  `
subject_cn=`echo "$subject" | grep -w 'CN:' | sed 's/^ *//' | sed 's/CN:/CN:  /'`
issuer=`cat $tempdir/ssl.txt | grep -m 1 -w 'Issuer:' | sed 's/, Inc//' | sed 's/,/\n/g'| sed 's/Issuer://g'`
issuer_country=`echo "$issuer" | grep -w 'C:' | tr -d ' ' | sed 's/C:/\/ /'`
issuer_cn=`echo "$issuer" | grep -w 'CN:' | sed 's/^ *//' | sed 's/CN:/CN:  /'`
echo -e -n "Expires:    "
cat $tempdir/ssl.txt | grep -i -m 1 'after' | cut -d ' ' -f 4-
echo -e  "\nSubject:    $subject_cn $subject_country"
echo -e  "\nIssuer:     $issuer_cn $issuer_country"
} 


#************************** dump certificates *********************************
function f_showCerts {
echo -e "\n\n=== $target Certificates ===\n"
date
echo -e "\n"
timeout 3 openssl s_client -connect $target:443 -showcerts
echo -e "\n________________________________________________________________\n"
echo -e "\n$target Public Key\n\n"
timeout 3 openssl s_client -connect $target:443 2>>/dev/null | openssl x509 -pubkey -noout
echo ''
}

#************************** HTTP- headers summary *********************************
function f_headers {
    curl -s -I -L --max-time 3 $target > $tempdir/headers.txt
    cat $tempdir/headers.txt | sed '/[Hh][Ii][Tt]/d' | sed '/[Mm][Ii][Ss][Ss]/d' | 
    sed '/[Dd][Aa][Tt][Ee]:/d' | sed '/{/d' | sed '/}/d' | sed '/[Rr]eport*/d' | sed '/[Vv]ary/d' | 
    sed '/[Cc]ontent-[Tt]ype:/d' | sed '/[Cc]ache-[Cc]ontrol/d' | sed '/[Ee]-[Tt][Aa][Gg]:/d' | 
    sed '/[Ee][Tt][A#a][Gg]/d' | sed '/[Aa]ge:/d' | sed '/[Cc]ontent-[Ll]ength:/d' |  
    sed '/[Ss]et-[Cc]ookie/d' | sed '/[Cc]ontent-[Ss]ecurity-[Pp]olicy:/d' | sed '/X-UA-Compatible/d' | 
    sed '/x-ua-compatible/d' |sed '/[Aa]ccept-[Rr]anges/d' | sed '/[Xx]-[Dd]ownload-[O#o]ptions/d' |
    sed '/[Xx]-[Tt]imer/d' | sed '/max_age/d' | sed '/[Ff]eature-[Pp]olicy/d' | sed '/[Xx]-[Cc]ache-*/d' | 
    sed '/x-tzla/d' | sed '/[Ee]xpect-[Cc][Tt]:/d' | sed '/[Ll]ast-[Mm]odified:/d'  | sed '/NEL:/d' | 
    sed '/-src/d' | sed '/[Xx]-[Vv]cs/d' | sed '/[Xx]-[Vv][Cc][Ss]-*/d' | sed '/[Vv]ia:/d' | 
    sed '/[Xx]-[Rr]equest-[Ii]d:/d' | sed '/[Ss]trict-[Tt]ransport-[Ss]ecurity:/d' | sed '/[Ee]xpires:/d' | 
    sed '/[Xx]-[Ff]rame-[Oo]ptions:/d' | sed '/[Xx]-[Ss]erved-[Bb]y:/d' | sed '/req-svc-chain:/d' | 
    sed '/[Rr]etry-[Aa]fter:/d' | sed '/[Kk]eep-[Aa]live:/d' | sed '/href=*/d' | sed '/[Ll]ink:/d' | 
    sed '/[Cc]onnection:/d' | sed '/[Aa]ccess-[Cc]ontrol-[Aa]llow-[Oo]rigin:/d' | sed '/[Xx]-[Rr]untime:/d' | 
    sed '/[Xx]-[Dd]ispatcher:/d' | sed '/[Pp]ragma:/d' | sed '/[Xx]-[Rr]ule:/d' | 
    sed '/[Xx]-[Pp]ermitted-[Cc]ross-[Dd]omain-[Pp]olicies:/d' | sed '/[Rr]eferrer-[Pp]olicy:/d' |
    fmt -w 80 -s  | tee -a $permdir/$file.txt
}

#******************* CMS guessing game (via keywords in src-links, response headers & robots.txt) *******
function f_guessCMS {
    if [ ! -f "$tempdir/headers.txt" ]; then
        curl -s -I -L --max-time 3 $target > $tempdir/headers.txt
    fi
    curl -s -L --max-time 4 $target/robots.txt > $tempdir/cms.txt
    curl -s -L --max-time 4 $target > $tempdir/target_src.txt
    cat $tempdir/headers.txt >> $tempdir/cms.txt
    cat $tempdir/target_src.txt | grep -w -A 1 "meta" | sed 's/^ *//' >> $tempdir/meta.txt
    cat $tempdir/target_src.txt | grep -w -A 1 "script=*" >> $tempdir/cms.txt
    cat $tempdir/target_src.txt | grep -w -A 1 "generator" | sed 's/^ *//' >> $tempdir/cms.txt
    cms_type=`cat $tempdir/cms.txt | grep -i -o -F -econtao -edrupal -ejoomla -eliferay -etypo3 -ewordpress | tr '[a-z]' '[A-Z]' | sort | uniq`
    echo -e "${B}CMS:${D}  $cms_type"
    echo -e "\n\nCMS: $cms_type" >> $permdir/$file.txt
}

#************************** website title *********************************
function f_website_Title {
         echo -e "\nWebsite Title\n" >> $permdir/$file.txt
         if ! type lynx &> /dev/null; then
              cat $tempdir/target_src.txt | grep -o "<title>[^<]*" | tail -c +8 | fmt -w 90 -s | tee -a $permdir/$file.txt
         else
              lynx -accept_all_cookies -crawl -dump www.$target | grep TITLE | sed 's/THE_TITLE://' | sed 's/^ *//' | 
              tee -a $permdir/$file.txt
         fi
}

#*************************** content of <meta name=description...> tag *********************************
function f_targetDescription {
    echo -e "\n\nDescription\n" >> $permdir/$file.txt
    cat $tempdir/meta.txt | tr -d '"' | tr -d '<' | tr -d '>' | tr -d '/' | sed '/meta name=description content=/!d' |
    sed 's/meta/\nmeta/g' > $tempdir/content.txt
    cat $tempdir/content.txt | sed 's/meta name=description content=//' | sed 's/&#039;s/s/' | sed 's/link//' | 
    sed 's/meta name=twitter:card//' | sed 's/rel=canonical//' | sed 's/href/\nhref/' | sed 's/meta property=og:type//' | 
    sed 's/\!--/\n\!--/' | sed '/\!--/d' | sed '$!N; /^\(.*\)\n\1$/!P; D' | sed 's/^ *//' | sed 's/title/\ntitle/' | 
    sed '/name=theme-color/d' | sed '/href=*/d' | sed 's/&amp;/\&/' | fmt -w 70 -s  | 
    tee -a $permdir/$file.txt
}


#************************* geolocation data *********************************
function f_geoIP {
    curl -s https://ipapi.co/$address/json | tr -d '{' | tr -d '}' | tr -d ',' | tr -d ' "' | sed -r '/^\s*$/d' |
    fmt -w 70 -s > $tempdir/geo.txt
    asn=`cat $tempdir/geo.txt | tail -2 | head -1 | cut -d ':' -f 2 | sed 's/^ *//'`
    org=`cat $tempdir/geo.txt | tail -1 | cut -d ':' -f 2 | sed 's/^ *//'`
    country=`cat $tempdir/geo.txt | grep -w 'country_name' | cut -d ':' -f 2 | sed 's/^ *//'`
    city=`cat $tempdir/geo.txt | grep -w 'city' | cut -d ':' -f 2 | sed 's/^ *//'`
    zip=`cat $tempdir/geo.txt | grep -w 'postal'  | cut -d ':' -f 2 | sed 's/^ *//'`
    region=`cat $tempdir/geo.txt | grep -w 'region' | cut -d ':' -f 2 | sed 's/^ *//'`
    regcode=`cat $tempdir/geo.txt | grep -w 'region_code' | cut -d ':' -f 2 | sed 's/^ *//'`
    lat=`cat $tempdir/geo.txt | grep -w 'latitude' | cut -d ':' -f 2 | sed 's/^ *//'`
    lon=`cat $tempdir/geo.txt | grep -w 'longitude' | cut -d ':' -f 2 | sed 's/^ *//'`
    zone=`cat $tempdir/geo.txt | grep -w 'timezone' | cut -d ':' -f 2 | sed 's/^ *//'`
    offset=`cat $tempdir/geo.txt | grep -w 'utc_offset' | cut -d ':' -f 2 | sed 's/^ *//'`
    tld=`cat $tempdir/geo.txt | grep -w 'country_tld' | cut -d ':' -f 2 | sed 's/^ *//'`
    callcode=`cat $tempdir/geo.txt | grep -w 'country_calling_code' | cut -d ':' -f 2 | sed 's/^ *//'`
        echo "ASN:            $asn"                 
        echo "ORG:            $org"                 
        echo ''                                     
        echo "Country:        $country"             
        echo "IDD/ TLD:       $callcode/$tld"       
        echo "TimeZone:       $zone (UTC $offset)"  
        echo ''                                     
        echo "City:           $city"                
        echo "Region:         $region ($regcode)"   
        echo "Zip-Code:       $zip"                 
        echo "Latitude:       $lat"                 
        echo "Longitude:      $lon"                 
}

#**************************** host whois summary *********************************
function f_whosHost {
    whois $target > $tempdir/host-whois.txt
    cat $tempdir/host-whois.txt | sed '/^#/d' | sed '/^%/d' | sed '/icann.org/d' | sed '/NOTICE/d' |
    sed '/reflect/d' | sed '/Fax:/d' |sed '/Fax Ext:/d' | sed '/unsolicited/d' | sed '/HKIRC-Accredited/d' |
    sed /'how to'/d | sed '/queried/d' | sed '/Bundled/d' | sed '/Registry Domain ID:/d' | sed 's/^ *//' |
    sed "/^[[:space:]]*$/d"  > $tempdir/whois.txt
    grep -w -i -A 1 -m 1 "domain name:" $tempdir/whois.txt > $tempdir/whois2.txt
    grep -w -i "Domain:" $tempdir/whois.txt >> $tempdir/whois2.txt
    grep -w -m 1 -A 1 "Registrar:" $tempdir/whois.txt >> $tempdir/whois2.txt
    grep -w -i -s "Status:" $tempdir/whois.txt >> $tempdir/whois2.txt
    grep -w -s "Changed:" $tempdir/whois.txt >> $tempdir/whois2.txt
    grep -w "Company Chinese name:" $tempdir/whois.txt >> $tempdir/whois2.txt
    grep -w -m 1 "Registrar URL:" $tempdir/whois.txt >> $tempdir/whois2.txt
    grep -w -m 1 "Registrar Abuse Contact Email:"  $tempdir/whois.txt >> $tempdir/whois2.txt
    grep -w "Registry Creation Date:" $tempdir/whois.txt >> $tempdir/whois2.txt
    grep -w -s "Last Modified:" $tempdir/whois.txt >> $tempdir/whois2.txt
    grep -s -i "Expiry" $tempdir/whois.txt >> $tempdir/whois2.txt
    grep -w -m 1 "registrar:" $tempdir/whois.txt >> $tempdir/whois2.txt
    grep -w -m 1 "e-mail:" $tempdir/whois.txt >> $tempdir/whois2.txt
    grep -w -m 1 "website:" $tempdir/whois.txt >> $tempdir/whois2.txt
    grep -w -i -A 8 "nic-hdl:" $tempdir/whois.txt  >> $tempdir/whois2.txt
         echo '' >> $tempdir/whois2.txt
    grep -s -w -i -m 1 "Organization:" $tempdir/whois.txt >> $tempdir/whois2.txt
    grep -s -w -i -m 1 "Registrant Name:" $tempdir/whois.txt >> $tempdir/whois2.txt
    grep -s -w -i -m 1 "Country:" $tempdir/whois.txt >> $tempdir/whois2.txt
    grep -s -w -i -m 1 "State/Province" $tempdir/whois.txt >> $tempdir/whois2.txt
    grep -s -w -i -m 1 "Address:" $tempdir/whois.txt >> $tempdir/whois2.txt
    grep -s -w -i -m 1 "Registrant Street:" $tempdir/whois.txt >> $tempdir/whois2.txt
    grep -s -w -i -m 1 "Registrant City:" $tempdir/whois.txt >> $tempdir/whois2.txt
    grep -s -w -i -m 1 "Registrant Postal Code:" $tempdir/whois.txt >> $tempdir/whois2.txt
    grep -s -w -i -m 1 "Registrant Phone:" $tempdir/whois.txt >> $tempdir/whois2.txt
    grep -s -w -i -m 1 "Registrant Email:" $tempdir/whois.txt >> $tempdir/whois2.txt
    grep -s -w -B 1 -A 16 "ADMINISTRATIVE" $tempdir/whois.txt >> $tempdir/whois2.txt
    grep -s -w "Registrant:" $tempdir/whois.txt >> $tempdir/whois2.txt
    grep -s -w -i "Eligibility Type:" $tempdir/whois.txt >> $tempdir/whois2.txt
    grep -s -w -i "dnssec:" $tempdir/whois.txt >> $tempdir/whois2.txt
    grep -s -w -i -m 1 "source:" $tempdir/whois.txt >> $tempdir/whois2.txt
    cat $tempdir/whois2.txt | sed '$!N; /^\(.*\)\n\1$/!P; D' | sed 's/nic-hdl:/\nnic-hdl:/' |
    sed 's/Registrant:/\nRegistrant:/' | sed 's/Administrative/\nAdministrative/' |
    sed 's/Technical/\nTechnical/' | fmt -w 80 -s | tee -a $permdir/$file.txt
}

#************************** reverse whois summary  *********************************
function f_drwho {
    cat $tempdir/rev-whois-lookup.txt | sed '/^#/d' | sed '/^%/d'  | sed '/inject:/d' | sed '/\*/d' | sed '/Parent:/d' |
    sed '/NetType:/d' | sed '/OriginAS:/d' | sed '/tech-c*/d' | sed -r '/^\s*$/d' | sed '/Comment:/d' | sed '/Ref:/d' |
    sed '/ResourceLink:/d' | sed '/OrgAbuseRef:/d'  | sed '/StateProv:/d' | sed '/please/d' | sed "/^[[:space:]]*$/d" |
    fmt -w 80 -s > $tempdir/drwho.txt
        grep -s -i -w -m 1 "NetRange" $tempdir/drwho.txt > $tempdir/drwho2.txt
        grep -s -i -w -m 1 "CIDR" $tempdir/drwho.txt >> $tempdir/drwho2.txt
        grep -s -i -w -m 1 "NetName" $tempdir/drwho.txt >> $tempdir/drwho2.txt
        grep -s -i -w -m 1 "NetHandle" $tempdir/drwho.txt >> $tempdir/drwho2.txt
        grep -s -i -w -m 2 -A 7 "Organization" $tempdir/drwho.txt >> $tempdir/drwho2.txt
        grep -i -w -m 1 -A 3 "OrgNOCHandle" $tempdir/drwho.txt >> $tempdir/drwho2.txt
        grep -w -m 1 -A 3 "OrgAbuseHandle:" $tempdir/drwho.txt >> $tempdir/drwho2.txt
        grep -i -w -m 1 -A 3 "OrgTechHandle" $tempdir/drwho.txt >> $tempdir/drwho2.txt
        grep -i -w -m 2 -A 4 "inetnum" $tempdir/drwho.txt >> $tempdir/drwho2.txt
        grep -w -m 1 "admin-c" $tempdir/drwho.txt >> $tempdir/drwho2.txt
        grep -w -m 1 "mnt-by" $tempdir/drwho.txt >> $tempdir/drwho2.txt
        grep -w -m 1 "abuse-mailbox" $tempdir/drwho.txt >> $tempdir/drwho2.txt
        grep -w -m 1 -A 2 "organisation" $tempdir/drwho.txt >> $tempdir/drwho2.txt
        grep -w -m 1 -A 6 "role" $tempdir/drwho.txt >> $tempdir/drwho2.txt
        grep -i -w -m 2 -A 5 "person" $tempdir/drwho.txt  >> $tempdir/drwho2.txt
        grep -w -m 1 "nic-hdl" $tempdir/drwho.txt >> $tempdir/drwho2.tx
        grep -i -w -m 1 -A 6 "route:" $tempdir/drwho.txt >> $tempdir/drwho2.txt
    cat $tempdir/drwho2.txt | sed '$!N; /^\(.*\)\n\1$/!P; D' |sed 's/inetnum/\ninetnum/' | sed 's/CIDR/\nCIDR/' |
    sed 's/Organization/\nOrganization/' | sed 's/person/\nperson/' | sed 's/OrgAbuseHandle/\nOrgAbuseHandle/' |
    sed 's/OrgNOCHandle/\nOrgNOCHHandle/' | sed 's/OrgTechHandle/\nOrgTechHandle/' | sed 's/role/\nrole/' |
    sed 's/route/\nroute/' | fmt -w 80 -s | tee -a $permdir/$file.txt
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
        echo -e "Tracepath Results \n"             >> $permdir/$file.txt
        tracepath -b -m 22 $target                 | tee -a $permdir/$file.txt
    else
        f_Dashes
    fi
}

#********************* use lynx to scrape target website for hyperlinks *****
function f_linkDump {
    echo -e "\n      Link Dump"                 >> $permdir/$file.txt
    echo -e "   ----------------\n"             >> $permdir/$file.txt
    echo -e "    TARGET: $target \n"            >> $permdir/$file.txt
    if ! type lynx &> /dev/null; then
        echo "Please install lynx"
    else
        lynx -accept_all_cookies -dump -listonly www.$target
    fi
    echo ''
}

#**************************** search for hosts in assumed /24 block via reverse dns lookup *************
function f_getPrefixes {
    mx_url=`dig mx +short $target | rev | cut -c 2- | rev | cut -d " " -f 2-`
    ns_url=`dig ns +short $target | rev | cut -c 2- | rev | cut -d " " -f 2-`
   
            for a in $(echo $mx_url)
            do
                dig x +short $a | rev | cut -d '.' -f 2- | rev >> $tempdir/mx_prefixes.txt
            done
            for b in $(echo $ns_url)
            do
            dig x +short $b | rev | cut -d '.' -f 2- | rev >> $tempdir/ns_prefixes.txt
           done
}


function f_hostSearch {
    for i in `seq 1 255` ; do sublist="$sublist ${prefx}.$i" ; done
    for i in $sublist ; do
        ptr=`host $i | cut -d ' ' -f 5`
        echo "$i - $ptr" | sed '/NXDOMAIN/d'
    done
}

#**************************** checking if server allows unauthorized zone transfers  ********
function f_zoneTransfer {
    dig ns +short $target | rev | cut -c  2- | rev > $tempdir/ns.txt
    for i in $(cat $tempdir/ns.txt); do
        dig axfr @${i} $target
    done
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

#******************** submenu Domain - related options  **************************************
function f_menuDomain {
f_solidLong
echo -e "${B}  >>  Target: $target - $host_ip${D}\n"
    echo ''
    echo -e "  ${B}11)${D}   website overview\n        (headers summary, IP, CMS, title- & content tags, social media links)"
    echo -e "  ${B}12)${D}   A,AAAA,MX,NS,PTR,SOA & TXT records"
    echo -e "  ${B}13)${D}   certificate information"
    echo -e "  ${B}14)${D}   whois lookup options"
    echo -e "  ${B}15)${D}   geolocation options (ext.API)"
    echo -e "  ${B}16)${D}   HTTP headers / robots.txt / link dump"
    echo -e "  ${B}17)${D}   subdomain enumeration - options (ext.APIs)"
    echo -e "  ${B}18)${D}   address block reverse host search - options"
    echo -e "  ${B}19)${D}   reverse IP lookup (ext.API)" 
    echo -e "  ${B}20)${D}   zone transfer check"
    echo -e "  ${B}21)${D}   server response times & tracepath"
    f_solidShort
}

#******************** submenu IP - related options  **************************************
function f_menuIP {
    f_solidLong
    echo -e "${B}  >>  Target: $target${D}\n"
    echo ''
    echo -e "  ${B}31)${D}   dns & whois reverse lookup"
    echo -e "  ${B}32)${D}   HTTP headers summary & website title"
    echo -e "  ${B}33)${D}   target geolocation (ext. API)"
    echo -e "  ${B}34)${D}   certificate information"
    echo -e "  ${B}35)${D}   dump HTTP headers"
    echo -e "  ${B}36)${D}   link dump"
    echo -e "  ${B}37)${D}   address block reverse host search"
    echo -e "  ${B}38)${D}   reverse IP lookup (ext. API)"
    echo -e "  ${B}39)${D}   server response times & tracepath"
    f_solidShort
}


function f_whoisOptions {
    echo -e "${B}Reverse Whois Lookup Options\n"
    echo -e "  41)  host whois & reverse whois summary"
    echo -e "  42)  'First' MX record reverse whois summary"
    echo -e "  43)  SOA record reverse whois summary"
    f_solidShort
}

function f_geoOptions {
    echo -e "${B}Geolocation Options\n"
    echo -e "  51)  host geolocation"
    echo -e "  52)  'First' MX record geolocation"
    echo -e "  53)  SOA record geolocation"
    f_solidShort
}

function f_optionsFiledump {
    echo -e "${B}Dump to screen / file: \n"
    echo -e "  61)  HTTP headers"
    echo -e "  62)  robots.txt"
    echo -e "  63)  linkdump"
    f_solidShort
}

function f_subEnumOptions {
    echo -e "${B}Subdomain Enumeration Options\n"
    echo -e "  71)  search with hackertarget.com"
    echo -e "  72)  search with crt.sh"
    f_solidShort
}

function f_optionsHostSearch {
        echo -e "${B}address block reverse host search - options\n"
        echo "  81)  $target address block reverse host search      ($host_prefix.x)" 
        echo "  82)  MX record- address block reverse host search  ($mx_prefix.x)"
        echo "  83)  SOA- record address block reverse host search ($soa_prefix.x)"
        echo "  84)  custom- address block reverse host search"  
    f_solidShort
}

#*****************************************************************************
#***************************** main program loop *****************************
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
echo -e "\nResults will be stored inside \"drwho_results\" in your current working directory.\n "
echo -e "Please enter a file name:\n "
echo -e -n "  ${B}>>${D}  "
read file
# defining essential variables
host_ip=`echo | host -t A $target | head -1 | cut -d " " -f 4`
mx_url=`dig mx +short $target | rev | cut -c 2- | rev | cut -d " " -f 2-`
ns_url=`dig ns +short $target | rev | cut -c 2- | rev`
soa_url=`dig soa +short $target | cut -d ' ' -f 1 | rev | cut -c 2- | rev`
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
echo -e "\nResults will be stored inside \"drwho_results\" in your current working directory.\n "
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
f_makePermDir
f_textfileSeparator
echo -e "   Set Target ${B}AS${D} - e.g. AS8068 - or ${B}IP${D}\n"
echo -e -n "  ${B}>>${D}  "
read target_as
echo -e "\nResults will be stored inside \"drwho_results\" in your home folder.\n "
echo -e "Please enter a file name:\n "
echo -e -n "  ${B}>>${D}  "
read file
f_solidLong
echo -e "      AS Information"      >> $permdir/$file.txt
echo -e "   ----------------------\n\n" >> $permdir/$file.txt
echo -e "${B}Autonomous System Information (ext.API)${D}\n\n"
curl -s curl https://api.hackertarget.com/aslookup/?q=$target_as | tee -a $permdir/$file.txt
echo ''
f_solidLong
;;
11)
#************** 11) Website Overview ********************
f_makeNewDir
f_solidLong
f_textfileSeparator
echo -e "      Website Overview"          >> $permdir/$file.txt
echo -e "   ----------------------\n"    >> $permdir/$file.txt
error_code=6
curl -sf "${target}" > /dev/null
if [ $? = ${error_code} ];then
echo -e "${R} CONNECTION: FAILURE${D}\n"
continue
else
echo -e "${B}Server Status:  ${GR}ONLINE${D}"
echo -e " \nSERVER STATUS: ONLINE\n\n" >> $permdir/$file.txt
fi
echo -e "\n"
f_headers
#******** CMS, host IP addresses, website title & -description, social media links ********
echo -e "\n${B}Host IP Addresses${D}\n"
echo -e "\n\nHost IP Addresses\n" >> $permdir/$file.txt
host -t A $target | cut -d ' ' -f 4- | tee -a $permdir/$file.txt
echo -e "${G}---------------\033[0m"
echo -e "---------------" >> $permdir/$file.txt
host -t AAAA $target | cut -d ' ' -f 3- | tee -a $permdir/$file.txt
echo -e "\n"
f_guessCMS
f_solidLong
f_textfileSeparator
echo -e "${B}Website Title${D}\n"
f_website_Title
echo -e "\n\n${B}Description${D}\n"
f_targetDescription
f_solidLong
f_textfileSeparator
echo -e "${B}Social Media & Contact Links ${D}\n"
echo -e "Social Media & Contact Links \n" >> $permdir/$file.txt
lynx -accept_all_cookies -dump -listonly -nonumbers www.$target > $tempdir/socialmedia.txt
lynx -accept_all_cookies -dump -listonly -nonumbers www.$target/contact >> $tempdir/socialmedia.txt
lynx -accept_all_cookies -dump -listonly -nonumbers www.$target/kontakt >> $tempdir/socialmedia.txt
cat $tempdir/socialmedia.txt | grep -F -econtact -ediscord -ekontakt -econtatto -eimpressum -eetsy -efacebook -egithub -einstagram -elinkedin -epinterest -ereddit -etwitter -exing -eyoutube -emailto | sed '/sport/d' |  sed '/program/d' | 
sed 's/mailto:/\nmailto:/' | sed 's/mailto://' | sort | uniq | tee -a $permdir/$file.txt
f_solidLong
f_textfileSeparator
echo -e "${B}Certificate Status${D}\n"
echo -e "Certificate Status\n\n" >> $permdir/$file.txt
f_certQuick | tee -a $permdir/$file.txt
f_removeDir
f_solidLong
f_textfileSeparator
;;
12)
#********** 12) DNS Records - A, AAAA, MX, NS, PTR, SOA, TXT **********
f_solidLong
f_textfileSeparator
echo -e "      A, AA, NS, MX, PTR & SOA Records"          >> $permdir/$file.txt
echo -e "   --------------------------------------\n"    >> $permdir/$file.txt
dig a  +noall +answer  +nottlid $target     >> $permdir/$file.txt
dig aaaa +noall +answer  +nottlid $target   >> $permdir/$file.txt
echo ''                                     >> $permdir/$file.txt
dig mx  +noall +answer  +nottlid $target    >> $permdir/$file.txt
echo ''                                     >> $permdir/$file.txt
dig ns  +noall +answer  +nottlid $target    >> $permdir/$file.txt
echo -e "${B}$target A & AAAA Records${D}\n"
host -t A $target | cut -d ' ' -f 4-
echo -e "${G}---------------\033[0m"
host -t AAAA $target | cut -d ' ' -f 3-
echo -e "\n\n${B}$host_ip PTR Record${D}\n"
echo -e "\n\nPTR Record\n" >> $permdir/$file.txt
host -t A $host_ip | cut -d ' ' -f 3- | rev | cut -d '.' -f 2- | rev  | tee -a $permdir/$file.txt
echo -e "\n\n${B}MX Priorities${D}\n"
dig mx +short $target
echo -e "\n\n${B}SOA Record${D}\n"
echo -e "\n\nSOA Record\n"                   >> $permdir/$file.txt
dig soa +short $target | tee -a $permdir/$file.txt
f_solidLong
f_textfileSeparator
echo -e "      MX, NS  A & AAAA Records"       >> $permdir/$file.txt
echo -e "   -------------------------------\n" >> $permdir/$file.txt
echo -e "${B}MX, NS  A & AAAA Records${D}\n"
mx_url=`dig mx +short $target | rev | cut -c 2- | rev | cut -d " " -f 2-`
ns_url=`dig ns +short $target | rev | cut -c 2- | rev`
f_ipv4                                          | tee -a $permdir/$file.txt
echo -e "\n"                                    | tee -a $permdir/$file.txt
f_ipv6                                          | tee -a $permdir/$file.txt
f_solidLong
f_textfileSeparator
echo -e "${B}SRV Record(s)${D}\n "
echo -e "SRV Record(s)\n " >> $permdir/$file.txt
host -t SRV $target | tee -a $permdir/$file.txt
f_solidLong
f_textfileSeparator
echo -e "${B}TXT Record(s)${D}\n "
echo -e "TXT Record(s)\n " >> $permdir/$file.txt
dig txt +short $target | tee -a $permdir/$file.txt
f_solidLong
;;
13)
#***********************  13) server certificates **************************
f_textfileSeparator
echo -e "\n      Certificate Information"      >> $permdir/$file.txt
echo -e "   --------------------------------\n\n" >> $permdir/$file.txt
f_solidLong
echo -e "${B}Certificate Information${D}\n\n"
f_makeNewDir
f_certInfo | tee -a $permdir/$file.txt
echo ''
f_Dashes_long
echo -e -n "${B}Display certificates & public key? yes [y] | no [any key]${D}   "
read answer
if [ $answer = "y" ]
then
f_Dashes_long
f_showCerts | tee -a $permdir/$file.certificates.txt
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
f_textfileSeparator
f_makeNewDir
echo -e "\n      whois Summary"        >> $permdir/$file.txt
echo -e "   -------------------\n"   >> $permdir/$file.txt
echo -e "${B}$target Whois Summary${D}\n"
f_whosHost
f_textfileSeparator
f_solidLong
whois $host_ip > $tempdir/rev-whois-lookup.txt
echo -e "${B}Host Reverse Whois Summary${D}\n"
echo -e "\n     Host Reverse whois Summary"        >> $permdir/$file.txt
echo -e "   ---------------------------------\n"   >> $permdir/$file.txt
echo -e "    $target - $host_ip \n\n" >> $permdir/$file.txt
f_drwho
f_removeDir
f_solidLong
f_whoisOptions
;;
42)
#******************* 42) mx- record reverse whois" **********************
f_solidLong
f_makeNewDir
mx_url=`dig mx +short $target | rev | cut -c 2- | rev | cut -d " " -f 2-`
mx_first_url=`echo "$mx_url" | sort | head -1`
mx_first_ip=`host -t A $mx_first_url | cut -d ' ' -f 4- | sort | head -1`
whois $mx_first_ip > $tempdir/rev-whois-lookup.txt
echo -e "${B}MX Record Reverse whois Summary${D}\n"
echo -e " ${BDim}$mx_first_url - $mx_first_ip${D}\n"
f_textfileSeparator
echo -e "\n     MX Reverse whois Summary"         >> $permdir/$file.txt
echo -e "   -------------------------------\n"    >> $permdir/$file.txt
echo -e "    $mx_first_url - $mx_first_ip\n\n" >> $permdir/$file.txt
f_drwho
echo -e "\n${BDim}The results shown are for the \nMX record that comes first in either \npriority or alphabetical order${D}" |
tee -a $permdir/$file.txt
f_removeDir
f_solidLong
f_whoisOptions
;;
43)
#******************* 43) soa- record reverse whois" **********************
f_solidLong
f_textfileSeparator
f_makeNewDir
soa_url=`dig soa +short $target | cut -d ' ' -f 1 | rev | cut -c 2- | rev`
soa_ip=`host -t A $soa_url | cut -d ' ' -f 4-`
whois $soa_ip > $tempdir/rev-whois-lookup.txt
echo -e "${B}SOA Record Reverse whois Summary\n"
echo -e " ${BDim}$soa_url - $soa_ip${D}\n"
echo -e "\n     SOA Reverse whois Summary"         >> $permdir/$file.txt
echo -e "   --------------------------------\n"    >> $permdir/$file.txt
echo -e "    $soa_url - $soa_ip\n\n" >> $permdir/$file.txt
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
f_makeNewDir
f_solidLong
f_textfileSeparator
echo -e "${B}Host IP Geolocation${D}\n"
echo -e " ${BDim}$target - $host_ip${D}"
echo -e "\n      Host Geolocation"        >> $permdir/$file.txt
echo -e "   -----------------------\n"  >> $permdir/$file.txt
echo -e "    $target - $host_ip \n\n" >> $permdir/$file.txt
address=`echo $host_ip`
echo ''
f_geoIP | tee -a $permdir/$file.txt
f_removeDir
f_solidLong
f_geoOptions
;;
52)
#******************* 52) geolocation data for "first" MX record (first in either priority or alphabetical order)********
f_makeNewDir
f_solidLong
f_textfileSeparator
mx_url=`dig mx +short $target | rev | cut -c 2- | rev | cut -d " " -f 2-`
mx_first_url=`echo "$mx_url" | sort | head -1`
mx_first_ip=`host -t A $mx_first_url | cut -d ' ' -f 4- | sort | head -1`
whois $mx_first_ip > $tempdir/rev-whois-lookup.txt
echo -e "${B}MX Record Geolocation\n"
echo -e " ${BDim}$mx_first_url - $mx_first_ip${D}\n"
echo -e "\n      MX Geolocation"         >> $permdir/$file.txt
echo -e "   ---------------------\n"    >> $permdir/$file.txt
echo -e "    $mx_first_url - $mx_first_ip\n\n" >> $permdir/$file.txt
address=`echo $mx_first_ip`
f_geoIP | tee -a $permdir/$file.txt
echo -e "\n${BDim}The results shown above are for the \nMX record that comes first in either \npriority or alphabetical order${D}" |
tee -a $permdir/$file.txt
f_removeDir
f_solidLong
f_geoOptions
;;
53)
#******************* 53) geolocation data for SOA record ********
f_makeNewDir
f_solidLong
f_textfileSeparator
echo -e "${B}SOA Record Geolocation${D}\n"
soa_url=`dig soa +short $target | cut -d ' ' -f 1 | rev | cut -c 2- | rev`
soa_ip=`host -t A $soa_url | cut -d ' ' -f 4-`
echo -e " ${BDim}$soa_url - $soa_ip${D}\n"
echo -e "\n      SOA Geolocation"        >> $permdir/$file.txt
echo -e "   ----------------------\n"    >> $permdir/$file.txt
echo -e "    $soa_url - $soa_ip\n\n" >> $permdir/$file.txt
address=`echo $soa_ip`
f_geoIP | tee -a $permdir/$file.txt
f_removeDir
f_solidLong
f_geoOptions
;;
16)
#************** 16) file dump options ********************
f_solidLong
f_optionsFiledump
;;
61)
#************** 61) dump HTTP - headers ********************
f_solidLong
f_textfileSeparator
echo -e "${B}HTTP Headers${D}\n"
echo -e "\n      HTTP-Headers"        >> $permdir/$file.txt
echo -e "   ------------------\n"     >> $permdir/$file.txt
curl -s -I -L --max-time 4 $target    | tee -a $permdir/$file.txt
f_solidLong
f_optionsFiledump
;;
62)
#************** 62) dump robots.txt - File ********************
f_solidLong
f_textfileSeparator
echo -e "${B}robots.txt${D}\n"
echo -e "      robots.txt"           >> $permdir/$file.txt
echo -e "   -----------------\n"     >> $permdir/$file.txt
curl -s -L $target/robots.txt        | tee -a $permdir/$file.txt
echo ''
f_solidLong
f_optionsFiledump
;;
63)
#************** 63) link dump *****************
f_solidLong
f_textfileSeparator
echo -e "${B}Link Dump${D}\n"
f_linkDump | tee -a $permdir/$file.txt
echo ''
f_solidLong
f_optionsFiledump
;;
17)
f_solidLong
f_subEnumOptions
;;
71)
#*******************  71) subdomain enumeration via hackertarget.com - API **********************
f_solidLong
echo -e "${B}$target Subdomains (via hackertarget.com)${D}\n\n"
echo -e "\n"                                 >> $permdir/$file.subdomains.txt
echo -e "\n      Subdomains (hackertarget.com)"      >> $permdir/$file.subdomains.txt
echo -e "   ------------------------------------\n"  >> $permdir/$file.subdomains.txt
echo -e "$target - $host_ip"                         >> $permdir/$file.subdomains.txt
date                                                 >> $permdir/$file.subdomains.txt
echo -e "\n"                                         >> $permdir/$file.subdomains.txt
curl -s https://api.hackertarget.com/hostsearch/?q=$target | sed 's/,/ -  /g' | tee -a $permdir/$file.subdomains.txt
echo ''
f_solidLong
f_subEnumOptions
;;
72)
#***********************  72) subdomain enumeration via crt.sh **************************
f_makeNewDir
f_solidLong
echo -e "${B}$target Subdomains (via crt.sh)${D}\n\n"
echo -e "\n"                                 >> $permdir/$file.subdomains.txt
echo -e "\n      Subdomains (crt.sh)"        >> $permdir/$file.subdomains.txt
echo -e "   ----------------------------\n"  >> $permdir/$file.subdomains.txt
echo -e "$target - $host_ip"                 >> $permdir/$file.subdomains.txt
date                                         >> $permdir/$file.subdomains.txt
echo -e "\n"                                 >> $permdir/$file.subdomains.txt
curl -s https://crt.sh/?q=$target > $tempdir/crt.txt
cat $tempdir/crt.txt | grep $target | sed 's/<TD>//' | sed 's/<\/TD>//' | sed 's/<BR>/\n/g' | sed 's/^ *//' | 
sed '/<TD/d' | sed '/<\/A>/d' | sed '/<TITLE>/d' | sed '/<TH/d' | sort | uniq | tee -a $permdir/$file.subdomains.txt
f_removeDir
f_solidLong
f_subEnumOptions
;;
18)
#*******************  18) address block reverse host search options **********************
f_solidLong
soa_ip=`host -t A $soa_url | cut -d ' ' -f 4-`
soa_prefix=`echo $soa_ip | rev | cut -d '.' -f 2- | rev`
host_prefix=`echo $host_ip | rev | cut -d '.' -f 2- | rev`
mx_first_url=`echo "$mx_url" | sort | head -1`
mx_first_ip=`host -t A $mx_first_url | cut -d ' ' -f 4- | sort | head -1`
mx_prefix=`echo $mx_first_ip | rev | cut -d '.' -f 2- | rev`
f_optionsHostSearch
;;
81)
#*******************  81) domain a record address block reverse host search **********************
f_solidLong
f_textfileSeparator
echo -e "${B}$host_ip Address Block Reverse Host Search${D}\n\n"
echo -e "\n      Reverse Host Search"           >> $permdir/$file.txt
echo -e "   ---------------------------\n"    >> $permdir/$file.txt
prefx=`dig x +short $target | rev | cut -d '.' -f 2- | rev`
f_hostSearch | tee -a  $permdir/$file.txt
echo '' | tee -a  $permdir/$file.txt
f_solidLong
f_optionsHostSearch
;;
82)
#*******************  82) mx record address block reverse host search **********************
f_solidLong
f_textfileSeparator
echo -e "${B}MX - Address Block Reverse Host Search${D}\n\n"
echo -e "\n   MX Record - Address Block Reverse Host Search"           >> $permdir/$file.txt
echo -e "   -------------------------------------------------\n"       >> $permdir/$file.txt
prefx=`echo $mx_first_ip | rev | cut -d '.' -f 2- | rev`
f_hostSearch | tee -a  $permdir/$file.txt
echo '' | tee -a  $permdir/$file.txt
f_solidLong
f_optionsHostSearch
;;
83)
#*******************  83) soa record address block reverse host search **********************
f_solidLong
f_textfileSeparator
echo -e "${B}SOA - Address Block Reverse Host Search${D}\n\n"
echo -e "\n   SOA Record - Address Block Reverse Host Search"           >> $permdir/$file.txt
echo -e "   ---------------------------------------------------\n"      >> $permdir/$file.txt
prefx=`echo $soa_ip | rev | cut -d '.' -f 2- | rev`
f_hostSearch | tee -a  $permdir/$file.txt
echo '' | tee -a  $permdir/$file.txt
f_solidLong
f_optionsHostSearch
;;
84)
#*******************  84) custom address block reverse host search **********************
f_makeNewDir
f_getPrefixes 
f_solidLong
f_textfileSeparator
echo -e "\n    Custom Reverse Host Search"           >> $permdir/$file.txt
echo -e "   --------------------------------\n"      >> $permdir/$file.txt
echo -e "${B}Reverse Host Search - Custom Input${D}\n"
echo -e "For further enumeration you may want to pick one of the following IPv4-prefixes:" 
echo -e "\nIPv4 Prefixes (MX- Records):\n" | tee -a  $permdir/$file.txt
cat $tempdir/mx_prefixes.txt | sort | uniq | tee -a  $permdir/$file.txt
echo -e "\nIPv4 Prefix (NS- Records):\n" | tee -a  $permdir/$file.txt
cat $tempdir/ns_prefixes.txt | sort | uniq | tee -a  $permdir/$file.txt
echo -e "\nPlease enter a network prefix:\n "
echo -e -n "  ${B}>>${D}  "
read prefx
echo ''
f_hostSearch | tee -a  $permdir/$file.txt
echo '' | tee -a  $permdir/$file.txt
f_removeDir
f_solidLong
f_optionsHostSearch
;;
19)
#*******************  19) reverse IP lookup via hackertarget.com - API **********************
f_solidLong
f_textfileSeparator
echo -e "${B}Reverse IP Lookup${D}\n"
echo -e "\n      Reverse IP Lookup"      >> $permdir/$file.txt
echo -e "   ------------------------\n" >> $permdir/$file.txt
curl -s https://api.hackertarget.com/reverseiplookup/?q=$host_ip | tee -a $permdir/$file.txt
echo -e "\n" | tee -a $permdir/$file.txt
f_solidLong
;;
20)
#*******************  20) check if unauthorized zone transfers are permitted **********************
f_makeNewDir
f_solidLong
f_textfileSeparator
echo -e "${B}Zone Transfer Check${D}\n "
echo -e "\n      Zone Transfer Check"         >> $permdir/$file.txt
echo -e "   ---------------------------\n"  >> $permdir/$file.txt
f_zoneTransfer                              | tee -a $permdir/$file.txt
f_removeDir
f_solidLong
;;
21)
#************** 21) server response times & tracepath ********************
f_solidLong
f_textfileSeparator
echo -e "${B}Server Response Times${D}"
echo -e "      Server Response Times"          >> $permdir/$file.txt
echo -e "   ----------------------------\n"     >> $permdir/$file.txt
error_code=6
curl -sf "${target}" > /dev/null
 if [ $? = ${error_code} ];then
echo -e " ${R}CONNECTION: FAILURE ${D}\n" | tee -a $permdir/$file.txt
continue
else
echo -e "\n ${B}$target Status:  ${GR}ONLINE${D}"
echo -e "    \nSERVER STATUS: ONLINE\n"          >> $permdir/$file.txt
fi
echo -e "\n ${BDim}$target - $host_ip${D}"
echo -e "   TARGET: $target - $host_ip\n"        >> $permdir/$file.txt
f_resTime       | tee -a $permdir/$file.txt
f_tracePath
f_solidLong
;;
31)
#******************* 31) target - dns & whois reverse lookup   **********************
f_makeNewDir
f_solidLong
f_textfileSeparator
echo -e "${B}target PTR & reverse whois${D}\n\n"   
echo -e "\n      whois & PTR"              >> $permdir/$file.txt
echo -e "   ----------------\n"         >> $permdir/$file.txt
echo -e "$target PTR Record\n" >> $permdir/$file.txt
echo -e "${B}$target PTR Record${D}\n"
host -t A $target | cut -d ' ' -f 3- | rev | cut -d '.' -f 2- | rev | tee -a $permdir/$file.txt
echo -e "\n"  >> $permdir/$file.txt
whois $target > $tempdir/rev-whois-lookup.txt
echo -e "\n\n${B}$target Reverse Whois Summary${D}\n"
echo -e "\n     Host Reverse whois Summary"        >> $permdir/$file.txt
echo -e "   -------------------------------\n"   >> $permdir/$file.txt
f_drwho
f_removeDir
f_solidLong
;;
32)
#******************* 32) headers summary & website title  **********************
f_makeNewDir
f_solidLong
f_textfileSeparator
error_code=6
curl -sf "${target}" > /dev/null
if [ $? = ${error_code} ];then
echo -e "${R} CONNECTION: FAILURE${D}\n" | tee -a $permdir/$file.txt
continue
else
echo -e "${B}Server Status:  ${GR}ONLINE${D}"
echo -e "\n TARGET: $target\n"
echo -e " SERVER STATUS: ONLINE\n\n"          >> $permdir/$file.txt
fi
echo -e "\n"
f_headers
f_solidLong
echo -e "\n${B}$target PTR Record${D}\n"
echo -e "\n\n$target PTR Record\n" >> $permdir/$file.txt
host -t A $target | cut -d ' ' -f 3- | rev | cut -d '.' -f 2- | rev
echo ''
f_website_Title
f_removeDir
f_solidLong
;;
33)
#******************* 33) target geolocation via ip-api.co  **********************
f_makeNewDir
f_makeNewDir
f_solidLong
f_textfileSeparator
echo -e "${B}$target Geolocation${D}\n"
echo -e "\n     IP Geolocation"         >> $permdir/$file.txt
echo -e "   ----------------------\n"     >> $permdir/$file.txt
echo -e "    - $target - \n\n" >> $permdir/$file.txt
address=`echo $target`
f_geoIP | tee -a $permdir/$file.txt
f_removeDir
f_solidLong
;;
34)
#***********************  34) server information & -file **************************
f_makeNewDir
f_solidLong
f_textfileSeparator
echo -e "\n      Certificate Information"       >> $permdir/$file.txt
echo -e "   --------------------------------\n" >> $permdir/$file.txt
echo -e "     TARGET: $target\n\n"                      >> $permdir/$file.txt
echo -e "${B}Certificate Information${D}\n"
f_certInfo | tee -a $permdir/$file.txt
echo -e "\n"
f_Dashes_long
echo -e -n "${B}Display certificates & public key? yes [y] | no [any key]${D}   "
read answer
if [ $answer = "y" ]
then
f_Dashes_long
f_showCerts                         | tee -a $permdir/$file.txt
fi
f_removeDir
f_solidLong
;;
35)
#***********************  35) dump HTTP - headers **************************
f_solidLong
f_textfileSeparator
echo -e "${B}$target HTTP Headers${D}\n"
echo -e "\n      HTTP-Headers"            >> $permdir/$file.txt
echo -e "  ---------------------\n"       >> $permdir/$file.txt
echo -e "    TARGET: $target\n\n"                 >> $permdir/$file.txt
curl -s -I -L --max-time 4 $target  | tee -a $permdir/$file.txt
echo ''
f_solidLong
;;
36)
#***********************  36) link dump  **************************
f_solidLong
f_textfileSeparator
echo -e "${B}$target Link Dump${D}\n"
f_linkDump                          | tee -a $permdir/$file.txt
echo ''
f_solidLong
;;
37)
#*******************  37) address block reverse host search **********************
f_solidLong
f_textfileSeparator
echo -e "${B}Address Block Reverse Host Search${D}\n\n"
echo -e "\n      Reverse Host Search"       >> $permdir/$file.txt
echo -e "   --------------------------\n\n" >> $permdir/$file.txt
prefx=`echo $target | rev | cut -d '.' -f 2- | rev`
f_hostSearch  | tee -a  $permdir/$file.txt
f_solidLong
;;
38)
#******************* 38) reverse IP lookup via hackertarget.com - API **********************
f_solidLong
f_textfileSeparator
echo -e "${B}Reverse IP Lookup${D}\n"
echo -e " ${BDim}Target: $target${D}\n\n"
echo -e "\n      Reverse IP Lookup"        >> $permdir/$file.txt
echo -e "   ------------------------\n"    >> $permdir/$file.txt
echo -e "      TARGET: $target\n\n"        >> $permdir/$file.txt
curl -s https://api.hackertarget.com/reverseiplookup/?q=$target | tee -a $permdir/$file.txt
echo -e "\n" | tee -a $permdir/$file.txt
f_solidLong
;;
39)
#******************* 39) server status, response times & tracepath  **********************
f_solidLong
f_textfileSeparator
error_code=6
curl -sf "${target}" > /dev/null
 if [ $? = ${error_code} ];then
echo -e " ${R}CONNECTION: FAILURE ${D}\n" | tee -a $permdir/$file.txt
continue
else
echo -e "${B}$target Status:  ${GR}ONLINE${D}"
echo -e " \nTARGET: $target\n"                >> $permdir/$file.txt
echo -e " SERVER STATUS: ONLINE\n\n"          >> $permdir/$file.txt
fi
echo -e "\n\n${B}Server Response Times${D}\n"
f_resTime                                 | tee -a $permdir/$file.txt
f_tracePath
f_solidLong
;;
#******************* 0) exit  **********************
0)
f_textfileSeparator
echo -e "\n Bye! \n" >> $permdir/$file.txt
f_removeDir
echo -e "\n${B}----------------------------- Done ------------------------------\n"
echo -e "                  ${BDim}Author - Thomas Wy, June 2020${D}\n\n"
break
;;
esac
done


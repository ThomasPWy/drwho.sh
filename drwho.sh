#!/bin/bash
#************** Variables - colors & temp. directory ***************
B='\033[1;34m'
BDim='\033[0;34m'
D='\033[0m'
GREY='\033[1;30m'
GR='\033[1;32m'
R='\033[1;31m'

tempdir="$PWD/drwho_temp"

#************** drwho - banner *************

echo -e "${B}\n
 ____                _           
|  _ \ _ ____      _| |__   ___  
| | | | '__\ \ /\ / / '_ \ / _ \ 
| |_| | |   \ V  V /| | | | (_) |
|____/|_|    \_/\_/ |_| |_|\___/ 
                                 
${D}"
echo -e "\033[3;39m \"whois the Doctor? Who? Dr who?\" ${D}\n"

#*************** Functions ***************


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
echo ''
}

#************ separators (solid, dashed) *************
function f_solidLong {
    echo -e "\n${GREY}________________________________________________________________________${D}\n"
}

function f_solidLineText {
    echo -e "\n\n________________________________________________________________________\n\n" >> $out
}

function f_solidShort {
    echo -e "${BDim}      ____${D}\n"
}

function f_Dashes {
     echo -e "--------------------------------------------------"
}

function f_DashesBlue {
     echo -e "${B}--------------------------------------------------${D}"
}


function f_Dashes_long {
     echo -e "${B}--------------------------------------------------------------------${D}"
}


function f_connCheck {
error_code=6
curl -sf "${target}" > /dev/null
if [ $? = ${error_code} ];then
echo -e "${R} CONNECTION: FAILURE${D}\n"
echo -e "\n\n CONNECTION: FAILURE\n" >> $out
continue
else
echo -e "\n${B}$target Status:  ${GR}ONLINE${D}"
echo -e "$target Status:  ONLINE \n" >> $out
fi
}

function f_aRecord {
host -t A $target | cut -d ' ' -f 4-
echo -e "---------------"
host -t AAAA $target | cut -d ' ' -f 3-
}

#********************************* mail- & name server A & AAAA records  *********************************

function f_mxIPv4 {
            for i in $(echo $mx_url)
            do
                echo | host -t A $i | sed -e s/'has'/'\n'/ | sed s/address// | tee -a $out
                echo '' | tee -a $out
            done
}

function f_nsIPv4 {
            for i in $(echo $ns_url)
            do
             echo | host -t A $i | sed -e s/'has'/'\n'/ | sed s/address// | tee -a $out
             echo '' | tee -a $out
           done
}

function f_mxIPv6 {
        for i in $(echo $mx_url)
        do
            echo | host -t AAAA $i | sed -e s/'has'/'\n'/ | sed s/address// | tee -a $out
            echo '' | tee -a $out
        done
}

function f_nsIPv6 {
        for i in $(echo $ns_url)
        do
            echo | host -t AAAA $i | sed -e s/'has'/'\n'/ | sed s/address// | tee -a $out
            echo '' | tee -a $out
        done
}

#************ certificate status & algorithms *************
function f_certInfo {
subject=`cat $tempdir/ssl.txt | grep -m 1 -w 'Subject:' | sed 's/, Inc/ Inc/' | sed 's/,/\n/g' | sed 's/Subject://g'`
subject_org=`echo "$subject" | grep -w 'O:' | sed 's/^ *//' | sed 's/O:/Org: /'`
subject_location=`echo "$subject" | grep -w 'L:' | tr -d ' '  | sed 's/L:/\/ /' | sed 's/^ *//'`
subject_country=`echo "$subject" | grep -w 'C:' | tr -d ' ' | sed 's/C:/\/ /'`
subject_cn=`echo "$subject" | grep -w 'CN:' | sed 's/^ *//' | sed 's/CN:/CN:  /'`
subject_name=`echo "$subject" | grep -w 'CN:' | sed 's/CN://' | sed 's/^ *//'`
issuer=`cat $tempdir/ssl.txt | grep -m 1 -w 'Issuer:' | sed 's/, Inc//' | sed 's/,/\n/g'| sed 's/Issuer://g'`
issuer_org=`echo "$issuer" | grep -w 'O:' | sed 's/^ *//' | sed 's/O:/Org: /'`
issuer_location=`echo "$issuer" | grep -w 'L:' | tr -d ' '  | sed 's/L:/\/ /' | sed 's/^ *//'`
issuer_country=`echo "$issuer" | grep -w 'C:' | tr -d ' ' | sed 's/C:/\/ /'`
issuer_cn=`echo "$issuer" | grep -w 'CN:' | sed 's/^ *//' | sed 's/CN:/CN:  /'`
issuer_name=`echo "$issuer" | grep -w 'CN:' | sed 's/CN://' | sed 's/^ *//'`
verification=`cat $tempdir/ssl.txt | grep -m 1 -w 'Verification:' | sed 's/Verification://' | sed 's/^ *//'`
cipher=`cat $tempdir/ssl.txt | grep -i -m 1 'ciphersuite' | cut -d ':' -f 2-`
protocol=`cat $tempdir/ssl.txt | grep -i -m 1 'protocol' | cut -d ':' -f 2-`
algo=`cat $tempdir/ssl.txt | grep -i -m 1 'algorithm' | sed s/'With'/' with '/g  | sed s/'Encryption'/' Encryption'/g |
cut -d ':' -f 2-`
key_algo=`cat $tempdir/ssl.txt | grep -i -m 1 -A 2 'public' | sed '/Info/d' |  sed '/Algorithm:/d'  |
sed 's/Public-Key//' | sed 's/ : /, /' | sed 's/^ *//g'`
echo -e -n "Expires:    "
cat $tempdir/ssl.txt | grep -i -m 1 'after' | cut -d ' ' -f 4-
echo -e  "\nSubject:    $subject_name"
echo -e  "\nIssuer:     $issuer_name"
echo -e  "\nverify:     $verification"
echo -e "\n\nTLS-Vers.: $protocol"
echo -e "\nCipher:    $cipher"
echo -e "\nSignature: $algo"
echo -e "\nPublicKey:  $key_algo"
}

#************ certificate chain *************
function f_certChain {
root_ca=`cat $tempdir/ssl.txt | grep -i -m 1 -A 1 'depth=2' | sed 's/depth=2//' | sed 's/,/\n/g' | sed '/postal/d' |
sed '/street:/d' | sed 's/^ *//' | sed 's/verify/\nverify/' | sed 's/return:/return: /'`
root_ca_org=`echo "$root_ca" | grep -w 'O:' | sed 's/^ *//' | sed 's/O:/Org: /'`
root_ca_country=`echo "$root_ca" | grep -w 'C:' | tr -d ' ' | sed 's/C:/\/ /' | sed 's/^ *//'`
root_ca_location=`echo "$root_ca" | grep -w 'L:' | tr -d ' '  | sed 's/L:/\/ /' | sed 's/^ *//'`
root_ca_cn=`echo "$root_ca" | grep -w 'CN:' | sed 's/^ *//' | sed 's/CN:/CN:  /'`
ca=`cat $tempdir/ssl.txt | grep -i -m 1 -A 1 'depth=1' | sed 's/depth=1//' | sed 's/,/\n/g'`
ca_org=`echo "$ca" | grep -w 'O:' | sed 's/^ *//' | sed 's/O:/Org: /'`
ca_country=`echo "$ca" | grep -w 'C:' | tr -d ' ' | sed 's/C:/\/ /' | sed 's/^ *//'`
ca_location=`echo "$ca" | grep -w 'L:' | tr -d ' '  | sed 's/L:/\/ /' | sed 's/^ *//'`
ca_cn=`echo "$ca" | grep -w 'CN:' | sed 's/^ *//' | sed 's/CN:/CN:  /'`
subject=`cat $tempdir/ssl.txt | grep -m 1 -w 'Subject:' | sed 's/, Inc/ Inc/' | sed 's/,/\n/g' | sed 's/Subject://g'`
subject_org=`echo "$subject" | grep -w 'O:' | sed 's/^ *//' | sed 's/O:/Org: /'`
subject_location=`echo "$subject" | grep -w 'L:' | tr -d ' '  | sed 's/L:/\/ /' | sed 's/^ *//'`
subject_country=`echo "$subject" | grep -w 'C:' | tr -d ' ' | sed 's/C:/\/ /'  `
subject_cn=`echo "$subject" | grep -w 'CN:' | sed 's/^ *//' | sed 's/CN:/CN:  /'`
echo -e "\nRoot CA:    $root_ca_cn"
echo "            $root_ca_org $root_location $root_ca_country"
echo "$root_ca" | grep -i -w 'verify' | sed 's/return://' | sed 's/verify/                  verify/'
echo -e "\nIssuer:     $ca_cn"
echo "            $ca_org $ca_location $ca_country"
echo "$ca" | grep -i -w 'verify' | sed 's/return://' | sed 's/verify/                  verify/'
echo -e  "\nSubject:    $subject_cn"
echo "            $subject_org $subject_location $subject_country"
cat $tempdir/ssl.txt | grep -i -w -m 1 -A 1 'Constraints:' | sed "/constraints:/d" | sed "/Constraints:/d" | sed 's/CA:/            CA:   /'
}

#************ certificate summary *************
function f_certSummary {
timeout 3 openssl s_client -connect $target:443 -brief 2>$tempdir/ssl_sum2.txt
echo | timeout 3 openssl s_client -connect $target:443 2> $tempdir/status.txt -status >> $tempdir/status.txt
echo | timeout 3 openssl s_client -connect $target:443 2>>$tempdir/ssl_sum2.txt | openssl x509 -text -enddate >> $tempdir/ssl_sum2.txt
cat $tempdir/ssl_sum2.txt | tr -d '"' | sed 's/ = /: /g' | sed 's/_/ - /g' | tr -d '(' | tr -d ')' |
sed 's/^ *//' > $tempdir/ssl.txt
#*** subject ***
subject=`cat $tempdir/ssl.txt | grep -m 1 -w 'Subject:' | sed 's/, Inc/ Inc/' | sed 's/,/\n/g' | sed 's/Subject://g'`
subject_country=`echo "$subject" | grep -w 'C:' | tr -d ' ' | sed 's/C:/\/ /'`
subject_cn=`echo "$subject" | grep -w 'CN:' | sed 's/CN://' | sed 's/^ *//'`
issuer=`cat $tempdir/ssl.txt | grep -m 1 -w 'Issuer:' | sed 's/, Inc//' | sed 's/,/\n/g'| sed 's/Issuer://g'`
issuer_country=`echo "$issuer" | grep -w 'C:' | tr -d ' ' | sed 's/C:/\/ /'`
issuer_cn=`echo "$issuer" | grep -w 'CN:' | sed 's/CN://' | sed 's/^ *//'`
verification=`cat $tempdir/ssl.txt | grep -m 1 -w 'Verification:' | sed 's/Verification://' | sed 's/^ *//'`
echo -e -n "Expires:    "
cat $tempdir/ssl.txt | grep -i -m 1 'after' | cut -d ' ' -f 4-
echo -e  "\nSubject:    $subject_cn $subject_country"
echo -e  "\nIssuer:     $issuer_cn $issuer_country"
echo -e  "\nverify:     $verification"
}

#************************** dump certificates *********************************
function f_showCerts {
echo -e "\n\n=== $target CERTIFICATES ===\n"
echo -e "DATE:  $(date) \n\n"
timeout 3 openssl s_client -connect $target:443 -showcerts
echo -e "\n________________________________________________________________\n"
echo -e "\n$target PUBLIC KEY\n\n"
timeout 3 openssl s_client -connect $target:443 2>>/dev/null | openssl x509 -pubkey -noout
echo ''
}

#************************** HTTP- headers summary *********************************
function f_headers {
    curl -s -I -L -k --max-time 3 $target > $tempdir/headers.txt
    cat $tempdir/headers.txt | sed '/[Hh][Ii][Tt]/d' | sed '/[Mm][Ii][Ss][Ss]/d' | sed '/bsig:/d' | sed '/bid:/d' |
    sed '/[Dd][Aa][Tt][Ee]:/d' | sed '/{/d' | sed '/}/d' | sed '/[Rr]eport*/d' | sed '/[Vv]ary/d' |
    sed '/[Cc]ontent-[Tt]ype:/d' | sed '/[Cc]ache-[Cc]ontrol/d' | sed '/[Ee]-[Tt][Aa][Gg]:/d' |
    sed '/[Ee][Tt][A#a][Gg]/d' | sed '/[Aa]ge:/d' | sed '/[Cc]ontent-[Ll]ength:/d' | sed '/brequestid:/d' |
    sed '/[Ss]et-[Cc]ookie/d' | sed '/[Cc]ontent-[Ss]ecurity-[Pp]olicy:/d' | sed '/X-UA-Compatible/d' |
    sed '/x-ua-compatible/d' |sed '/[Aa]ccept-[Rr]anges/d' | sed '/[Xx]-[Dd]ownload-[O#o]ptions/d' |
    sed '/[Xx]-[Tt]imer/d' | sed '/max_age/d' | sed '/[Ff]eature-[Pp]olicy/d' | sed '/[Xx]-[Cc]ache-*/d' |
    sed '/x-tzla/d' | sed '/[Ee]xpect-[Cc][Tt]:/d' | sed '/[Ll]ast-[Mm]odified:/d'  | sed '/NEL:/d' |
    sed '/-src/d' | sed '/[Xx]-[Vv]cs/d' | sed '/[Xx]-[Vv][Cc][Ss]-*/d' | sed '/[Vv]ia:/d' |
    sed '/[Xx]-[Rr]equest-[Ii]d:/d' | sed '/[Ss]trict-[Tt]ransport-[Ss]ecurity:/d' | sed '/[Ee]xpires:/d' |
    sed '/[Xx]-[Ss]erved-[Bb]y:/d' | sed '/req-svc-chain:/d' | sed '/[Rr]etry-[Aa]fter:/d' | sed '/[Kk]eep-[Aa]live:/d' |
    sed '/href=*/d' | sed '/[Ll]ink:/d' | sed '/[Cc]onnection:/d' | sed '/[Aa]ccess-[Cc]ontrol-[Aa]llow-[Oo]rigin:/d' |
    sed '/[Xx]-[Rr]untime:/d' | sed '/[Xx]-[Dd]ispatcher:/d' | sed '/[Pp]ragma:/d' | sed '/[Xx]-[Rr]ule:/d' |
    sed '/[Xx]-[Pp]ermitted-[Cc]ross-[Dd]omain-[Pp]olicies:/d' | sed '/[Rr]eferrer-[Pp]olicy:/d' |
    sed '/[Xx]-[Cc]loud-[Tt]race-[Cc]ontext:/d' | sed '/[Xx]-[Vv]iew-[Nn]ame:/d' | sed '/[Tt]ransfer-[Ee]ncoding:/d' |
    sed '/[Xx]-ac:/d' | fmt -w 80 -s | tee -a $out
}

#******************* CMS guessing game (via keywords in src-links, response headers & robots.txt) *******
function f_guessCMS {
    if [ ! -f "$tempdir/headers.txt" ]; then
        curl -s -I -k -L --max-time 4 $target > $tempdir/headers.txt
    fi
   cat $tempdir/headers.txt >> $tempdir/cms.txt
    curl -s -L --max-time 4 $target/robots.txt >> $tempdir/cms.txt
    curl -s -k -L --max-time 4 $target > $tempdir/target_src.txt
    #cat $tempdir/headers.txt >> $tempdir/cms.txt
    cat $tempdir/target_src.txt | grep -w -A 1 "meta" | sed 's/^ *//' >> $tempdir/meta.txt
    cat $tempdir/target_src.txt | grep -w -A 1 "script=*" >> $tempdir/cms.txt
    cat $tempdir/target_src.txt | grep -w -A 1 "generator" | sed 's/^ *//' >> $tempdir/cms.txt
    cat $tempdir/meta.txt >> $tempdir/cms.txt
    cms_type=`cat $tempdir/cms.txt | grep -i -o -F -econtao -edrupal -ejoomla -eliferay -etypo3 -ewordpress | sed 's/wp-*/wordpress/' |
    tr '[a-z]' '[A-Z]' | sort | uniq`
    echo -e "\n\n${B}CMS:${D}  $cms_type"
    echo -e "\n\n\n== CMS == \n\n$cms_type \n" >> $out
}

#************************** website title *********************************
function f_website_Title {
if ! type lynx &> /dev/null; then
              cat $tempdir/target_src.txt | grep -o "<title>[^<]*" | tail -c +8 | fmt -w 90 -s
         else
              lynx -accept_all_cookies -crawl -dump www.$target | grep TITLE | sed 's/THE_TITLE://' | sed 's/^ *//'
         fi
}

#*************************** content of <meta name=description...> tag *********************************
function f_targetDescription {
cat $tempdir/meta.txt | tr -d '"' | tr -d '<' | tr -d '>' | tr -d '/' |sed '/meta name=description content=/!d' |
    sed 's/meta/\nmeta/g' > $tempdir/content.txt
    cat $tempdir/content.txt | sed '/meta name=description content=/!d' | sed 's/meta name=description content=//' |
    sed 's/&#039;s/s/' | sed 's/link//' | sed 's/meta name=twitter:card//' | sed 's/rel=canonical//' | sed 's/href/\nhref/' |
    sed 's/meta property=og:type//' | sed 's/\!--/\n\!--/' | sed '/\!--/d' | sed '$!N; /^\(.*\)\n\1$/!P; D' | sed 's/^ *//' |
    sed 's/title/\ntitle/' | sed '/name=theme-color/d' | sed '/href=*/d' | sed 's/&amp;/\&/' | fmt -w 70 -s | tee -a $out
}

#********************* use lynx to scrape target website for social media & contact hyperlinks *****
function f_socialLinks {
if ! type lynx &> /dev/null; then
        echo "Please install lynx"
else
lynx -accept_all_cookies -dump -listonly -nonumbers www.$target > $tempdir/socialmedia.txt
cat $tempdir/socialmedia.txt | grep -F -econtact -ediscord -ekontakt -econtatto -eimpressum -eetsy -efacebook -egithub -einstagram -elinkedin -epinterest -ereddit -etwitter -exing -eyoutube -emailto | sed '/sport/d' |  sed '/program/d' | sed 's/mailto:/\nmailto:/' | sed 's/mailto://' | sort | uniq | tee -a $out
fi
}

#********************* use lynx to scrape target website for hyperlinks *****
function f_linkDump {
if ! type lynx &> /dev/null; then
        echo "Please install lynx"
    else
        lynx -accept_all_cookies -dump -listonly www.$target | tee -a $out
    fi
    echo ''
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

#**************************** whois summary *********************************
function f_whoisRequest {
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
    sed 's/Technical/\nTechnical/' | fmt -w 80 -s | tee -a $out
}

#************************** reverse whois summary  *********************************
function f_drwho {
    cat $tempdir/rev-whois.txt | sed '/^#/d' | sed '/^%/d'  | sed '/inject:/d' | sed '/\*/d' | sed '/Parent:/d' |
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
        grep -i -w -m 2 -A 8 "person" $tempdir/drwho.txt  >> $tempdir/drwho2.txt
        grep -w -m 1 "nic-hdl" $tempdir/drwho.txt >> $tempdir/drwho2.tx
        grep -i -w -m 1 -A 6 "route:" $tempdir/drwho.txt >> $tempdir/drwho2.txt
    cat $tempdir/drwho2.txt | sed '$!N; /^\(.*\)\n\1$/!P; D' |sed 's/inetnum/\ninetnum/' | sed 's/CIDR/\nCIDR/' |
    sed 's/Organization/\nOrganization/' | sed 's/person/\nperson/' | sed 's/OrgAbuseHandle/\nOrgAbuseHandle/' |
    sed 's/OrgNOCHandle/\nOrgNOCHHandle/' | sed 's/OrgTechHandle/\nOrgTechHandle/' | sed 's/role/\nrole/' |
    sed 's/route/\nroute/' | fmt -w 80 -s | tee -a $out
 }

#************************* server response times *********************************
function f_resTime {
  curl $target -s -L -o /dev/null -w \
 "
 TOTAL:           %{time_total}

 connect:         %{time_connect}
 appconnect:      %{time_appconnect}
 start_transfer:  %{time_starttransfer}
 pretransfer:     %{time_pretransfer}

 dns_lookup:      %{time_namelookup}
 redirects:       %{time_redirect}

 IP:              %{remote_ip}
 URL:             %{url_effective}

 "
}

#**************************** optionally run trace path *********************************
function f_tracePath  {
    echo ''
    f_Dashes_long
    echo ''
    echo -e -n "Run tracepath?  ${BDim}[y] yes | no [any other key]${D}  "
    read answer
    if [ $answer = "y" ]
        then
        echo ''
        echo -e -n "Choose ${BDim}[4]${D} for ${BDim}IPv4${D} mode, ${BDim}[6]${D} for ${BDim}IPv6${D} mode or ${BDim}[b]${D} for ${BDim}both${D} "
        read IPvChoice
        echo ''
        f_Dashes_long
        echo -e "\n"
        if [ $IPvChoice = "4" ]
           then
        echo -e "\n\n\n== TRACEPATH RESULTS (IPv4) == \n\n" >> $out
        tracepath -4 -b -m 22 $target | tee -a $out
        elif [ $IPvChoice = "6" ]
           then
        echo -e "\n\n\n== TRACEPATH RESULTS (IPv6) == \n\n" >> $out
        tracepath -6 -b -m 22 $target | tee -a $out
        elif [ $IPvChoice = "b" ]
           then
        echo -e "\n\n\n== TRACEPATH RESULTS (IPv4) == \n\n" >> $out
        echo -e "\n\n\n ${B}Tracepath Results (IPv4)${D}\n\n"
        tracepath -4 -b -m 22 $target | tee -a $out
        echo -e "\n\n${B}Tracepath Results (IPv6)${D}\n\n"
        echo -e "\n\n\n== TRACEPATH RESULTS (IPv6) == \n\n" >> $out
        tracepath -6 -b -m 22 $target | tee -a $out
        else
        echo -e "\n${R}Please choose IPv4 or IPv6 mode${D}\n"
        fi
    else
        echo ''
        f_Dashes_long
    fi
}

#**************************** search for hosts in assumed /24 block via reverse dns lookup *************
function f_getPrefixes {
    mx_url=`dig mx +short $target | rev | cut -c 2- | rev | cut -d " " -f 2-`
    ns_url=`dig ns +short $target | rev | cut -c 2- | rev | cut -d " " -f 2-`

            for a in $(echo $mx_url)
            do
                dig +short $a | rev | cut -d '.' -f 2- | rev >> $tempdir/mx_prefixes.txt
            done
            for b in $(echo $ns_url)
            do
            dig +short $b | rev | cut -d '.' -f 2- | rev >> $tempdir/ns_prefixes.txt
           done
}

function f_hostSearch {
    for i in `seq 1 255` ; do sublist="$sublist ${prefx}.$i" ; done
    for i in $sublist ; do
        ptr=`host $i | cut -d ' ' -f 5`
        echo "$i - $ptr" | sed '/NXDOMAIN/d'
    done
    echo ''
}

#**************************** checking if server allows unauthorized zone transfers  ********
function f_zoneTransfer {
    dig ns +short $target | rev | cut -c  2- | rev > $tempdir/ns.txt
    for i in $(cat $tempdir/ns.txt); do
        dig axfr @${i} $target
    done
}

#*********** banner for output file *************
function f_textfileBanner {
    echo -e "    -------------"                        >> $out
    echo -e "       Drwho"                             >> $out
    echo -e "    -------------"                        >> $out
    echo -e "\nAuthor - Thomas Wy, August 2020\n"      >> $out
    echo -e "https://github.com/ThomasPWy/drwho.sh \n" >> $out
    echo -e "TARGET:  $target"                         >> $out
    echo -e "DATE:    $(date)"                         >> $out

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
echo -e "${B}  >>  Target: $target - $host_ip${D}\n"
    echo ''
    echo -e "  ${B}11)${D}   website overview\n        (headers summary, IP, CMS, title- & content tags, social media links)"
    echo -e "  ${B}12)${D}   A,AAAA,MX,NS,PTR,SOA & TXT records"
    echo -e "  ${B}13)${D}   domain whois & reverse whois lookup"
    echo -e "  ${B}14)${D}   whois lookup options"
    echo -e "  ${B}15)${D}   server certificates"
    echo -e "  ${B}16)${D}   IP geolocation (ext.API)"
    echo -e "  ${B}17)${D}   HTTP headers / robots.txt / link dump"
    echo -e "  ${B}18)${D}   IPv4 address block host search"
    echo -e "  ${B}19)${D}   subdomain enumeration options (ext.APIs)"
    echo -e "  ${B}20)${D}   AS information (ext. API)"
    echo -e "  ${B}21)${D}   reverse IP lookup (ext.API)"
    echo -e "  ${B}22)${D}   zone transfer check"
    echo -e "  ${B}23)${D}   server response times & tracepath"
    f_solidShort
}


#******************** submenu IP - related options  **************************************
function f_menuIP {
    echo -e "${B}  >>  Target: $target${D}\n"
    echo ''
    echo -e "  ${B}31)${D}   dns & whois reverse lookup"
    echo -e "  ${B}32)${D}   HTTP headers summary & website title"
    echo -e "  ${B}33)${D}   server certificates"
    echo -e "  ${B}34)${D}   IP geolocation (ext. API)"
    echo -e "  ${B}35)${D}   HTTP headers / link dump"
    echo -e "  ${B}36)${D}   IPv4 address block reverse host search"
    echo -e "  ${B}37)${D}   AS information (ext. API)"
    echo -e "  ${B}38)${D}   reverse IP lookup (ext. API)"
    echo -e "  ${B}39)${D}   server response times & tracepath"
    f_solidShort
}

#******************** submenus for other options  **************************************

function f_whoisOptions {
    echo -e "${B} 41)  primary name server reverse whois summary"
    echo -e " 42)  'first' MX record reverse whois summary"
    echo -e " 43)  custom whois request (domain)"
    echo -e " 44)  custom reverse whois request (IP) ${D}"
}

function f_geoOptions {
    echo -e "${B} 61)  primary name server geolocation"
    echo -e " 62)  custom IP geolocation ${D}"
}

function f_filedumpOptions {
    echo -e "${B} 71)  HTTP headers"
    echo -e " 72)  robots.txt"
    echo -e " 73)  linkdump ${D}"
}

function f_filedumpIP {
  echo -e "${B} 53)  HTTP headers"
  echo -e " 54)  link dump ${D}"
}

function f_subEnumOptions {
    echo -e " 91)  search via hackertarget.com"
    echo -e " 92)  search via crt.sh ${D}"
}

function f_optionsHostSearch {
        echo -e "${B} 81)  target A record address block reverse host search ($host_prefix.x)"
        echo -e " 82)  custom- address block reverse host search ${D}"
}

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
f_makeNewDir
f_solidLong
echo -e "  Set Target ${B}DOMAIN${D} - e.g. example.com\n"
echo -e -n "  ${B}>>${D}  "
read target
echo -e "\n"
echo -e -n " Save output to file?   ${BDim}yes [y]  |  no [any other key]${D}  "
read answer
if [ $answer = "y" ]
        then
echo -e "\n${B}Please enter a file name${D} \n\n(a .txt file will be created in your /home directory)\n"
echo -e -n "  ${B}>>${D}  "
read file
out="$HOME/$file.txt"
else
out="$tempdir/out.txt"
fi
host_ip=`host -t A $target | head -1 | cut -d " " -f 4`
host_prefix=`echo $host_ip | rev | cut -d '.' -f 2- | rev`
mx_url=`dig mx +short $target | rev | cut -c 2- | rev | cut -d " " -f 2-`
ns_url=`dig ns +short $target | rev | cut -c 2- | rev`
soa_url=`dig soa +short $target | cut -d ' ' -f 1 | rev | cut -c 2- | rev`
f_textfileBanner
f_solidLong
f_menuDomain
;;
2)
f_makeNewDir
f_solidLong
echo -e "   Set target ${B}IP${D} - e.g. 45.33.32.156\n"
echo -e -n "  ${B}>>${D}  "
read target
echo -e "\n"
echo -e -n " Save output to file?   ${BDim}yes [y]  |  no [any other key]${D}  "
read answer
if [ $answer = "y" ]
        then
echo -e "\n${B}Please enter a file name${D} \n\n(a .txt file will be created in your /home directory)\n"
echo -e -n "  ${B}>>${D}  "
read file
out="$HOME/$file.txt"
else
out="$tempdir/out.txt"
fi
f_textfileBanner
f_solidLong
f_menuIP
;;
3)
#************** 3), 4) SUBMENUS For DOMAIN & IP  OPTIONS ********************
f_solidLong
f_menuDomain
;;
4)
f_solidLong
f_menuIP
;;
5)
#************** 5) AS Information ********************
f_makeNewDir
f_solidLong
echo -e "   Set target ${B}AS${D} - e.g. AS8068 or  ${B}IP${D} - e.g. 45.33.32.156\n"
echo -e -n "  ${B}>>${D}  "
read target
echo -e "\n"
echo -e -n "Save output to file?  ${BDim}yes [y]  |  no [any key]${D}  "
read answer
if [ $answer = "y" ]
        then
echo -e "\n${B}Please enter a file name${D} \n\n(a .txt file will be created in your /home directory)\n"
echo -e -n "  ${B}>>${D}  "
read file
out="$HOME/$file.txt"
else
out="$tempdir/out.txt"
fi
f_textfileBanner
f_solidLong
f_solidLineText
echo -e "${B}Autonomous System Information (via hackertarget.com)${D}\n\n"
echo -e "== AUTONOMOUS SYSTEM INFORMATION (via hackertarget.com)== \n\n" >> $out
curl -s --max-time 4 https://api.hackertarget.com/aslookup/?q=$target | tee -a $out
echo ''
f_solidLong
f_removeDir
;;
11)
#************** 11) Website Overview (submenu domain) ********************
f_makeNewDir
f_solidLong
f_solidLineText
f_connCheck
echo -e "\n" | tee -a $out
f_headers
echo -e "\n${B}Host IP Addresses${D}\n"
echo -e "\n\n== HOST IP ADDRESSES ==\n\n" >> $out
f_aRecord | tee -a $out
f_guessCMS
f_solidLong
f_solidLineText
echo -e "\n${B}Website Title${D}\n"
echo -e "== WEBSITE TITLE ==\n" >> $out
f_website_Title | tee -a $out
echo -e "\n\n${B}Description${D}\n"
echo -e "\n\n\n== DESCRIPTION ==\n" >> $out
f_targetDescription | tee -a $out
f_solidLong
echo -e "\n${B}Social Media & Contact Links ${D}\n"
echo -e "\n\n\n== SOCIAL MEDIA & CONTACT LINKS ==\n" >> $out
f_socialLinks
f_solidLong
f_solidLineText
echo -e "\n${B}Certificate Status${D}\n"
echo -e "== CERTIFICATE STATUS ==\n" >> $out
f_certSummary | tee -a $out
f_solidLong
f_removeDir
;;
#********** 12) DNS Records - A, AAAA, MX, NS, PTR, SOA, TXT **********
12)
f_makeNewDir
f_solidLong
f_solidLineText
echo -e "\n${B}$target Domain Host A & AAAA Records${D}\n"
echo -e "== $target DOMAIN HOST A & AAAA RECORDS ==\n\n" >> $out
f_aRecord | tee -a $out
echo -e "\n\n${B}$host_ip PTR record${D}\n"
echo -e "\n\n\n== PTR RECORD ==\n" >> $out
host -t A $host_ip | cut -d ' ' -f 3- | rev | cut -d '.' -f 2- | rev | tee -a $out
echo -e "\n\n${B}SOA Record${D}\n"
echo -e "\n\n\n== SOA RECORD ==\n" >> $out
dig soa +short $target | tee -a $out
echo -e "\n\n${B}MX Priorities${D}\n"
echo -e "\n\n\n== MX PRIORITIES ==\n\n" >> $out
mx_priorties=`dig mx +short $target` 
echo "$mx_priorties" | sort -g | uniq | tee -a $out
f_solidLong
f_solidLineText
echo -e "\n${B}MX A Records${D}\n"
echo -e "== MX A RECORDS ==\n\n" >> $out
f_mxIPv4
echo -e "\n\n== NS A RECORDS ==\n\n" >> $out
echo -e "${B}\nNS A Records${D}\n"
f_nsIPv4
f_solidLong
f_solidLineText
echo -e "\n${B}MX AAAA Records${D}\n"
echo -e "== MX AAAA RECORDS ==\n\n" >> $out
f_mxIPv6
echo -e "${B}\nNS AAAA Records${D}\n"
echo -e "\n\n== NS AAAA RECORDS ==\n\n" >> $out
f_nsIPv6
f_solidLong
f_solidLineText
echo -e "\n${B}SRV Record(s)${D}\n"
echo -e "== TXT RECORDS(S) ==\n\n" >> $out
host -t SRV $target | tee -a $out
echo -e "\n\n${B}TXT Record(s)${D}\n"
echo -e "\n\n\n== TXT RECORDS(S) ==\n\n" >> $out
txt=`host -t TXT $target`
echo "$txt"  | fmt -w 80 -s | tee -a $out
f_solidLong
f_removeDir
;;
13)
#***********************  13) host whois & rev. whois summary (submenu domain) **************************
f_makeNewDir
f_solidLong
f_solidLineText
echo -e "\n${B}Host whois Summary${D}\n"
echo -e "== HOST WHOIS SUMMARY ==\n\n" >> $out
whois $target > $tempdir/host-whois.txt
f_whoisRequest
echo -e "\n\n${B}Host reverse whois Summary${D}\n\n"
echo -e "\n\n== HOST REVERSE WHOIS SUMMARY ==\n\n" >> $out
whois $host_ip > $tempdir/rev-whois.txt
f_drwho
echo ''
f_solidShort
f_whoisOptions
f_solidLong
f_removeDir
;;
14)
#************** 14) whois options (submenu domain) ********************
f_solidLong
echo -e "${B} whois Lookup Options\n"
f_whoisOptions
f_solidShort
;;
15)
#***********************  15) certificate information  & -file (submenu domain)  **************************
f_makeNewDir
f_solidLong
f_solidLineText
timeout 3 openssl s_client -connect $target:443 -brief 2>$tempdir/ssl_sum2.txt
echo | timeout 3 openssl s_client -connect $target:443 2>>$tempdir/status.txt -status >> $tempdir/status.txt
echo | timeout 3 openssl s_client -connect $target:443 2>>$tempdir/ssl_sum2.txt | openssl x509 -text -enddate >> $tempdir/ssl_sum2.txt
cat $tempdir/ssl_sum2.txt | tr -d '"' | sed 's/AES_/AES-/g' |  sed 's/ = /: /g' | sed 's/_/ - /g' | tr -d '(' | tr -d ')' |
sed 's/^ *//' > $tempdir/ssl.txt
echo -e "\n${B}Certificate Status & SSL/TLS Information${D}\n\n"
echo -e "== CERTIFICATE STATUS & SSL/TLS INFORMATION ==\n\n" >> $out
f_certInfo | tee -a $out
echo -e "\n\n\n${B}Certificate Chain (depth:2-1-0)${D}\n"
echo -e "\n\n\n== CERTIFICATE CHAIN (depth:2-1-0) == \n\n" >> $out
f_certChain | tee -a $out
echo -e "\n"
f_Dashes_long
echo ''
echo -e -n "Display Certificates & Public Key?  ${BDim}yes [y] | no [any other key]${D}  "
read answer
echo ''
f_Dashes_long
echo ''
if [ $answer = "y" ]
then
    f_showCerts | tee $HOME/$target.certificate.txt
fi
f_solidLong
f_removeDir
;;
16)
#************** 16) target IP geolocation via ip-api.co (submenu domain) ********************
f_makeNewDir
f_solidLong
f_solidLineText
echo -e "\n${B}Host IP Geolocation (via ip-api.co)${D}\n"
echo -e " ${BDim}$target - $host_ip${D}\n\n"
echo -e "== HOST IP GEOLOCATION (via ip-api.co) ==\n"  >> $out
echo -e " $target - $host_ip\n\n" >> $out
address=`echo $host_ip`
f_geoIP | tee -a $out
echo ''
f_solidShort
f_geoOptions
f_solidLong
f_removeDir
;;
17)
f_solidLong
echo -e "${B} Dump to Screen / File: \n"
f_filedumpOptions
f_solidShort
;;
18)
f_solidLong
echo -e "${B} Address Block Reverse Host Search - Options\n"
f_optionsHostSearch
f_solidShort
;;
19)
f_solidLong
echo -e "${B} Subdomain Enumeration - Options\n"
f_subEnumOptions
f_solidShort
;;
20)
#************** 20) AS Information (submenu domain) ********************
f_makeNewDir
f_solidLong
f_solidLineText
echo -e "${B}Autonomous System Information (via hackertarget.com)${D}\n\n"
echo -e "  Set target ${B}AS${D} - e.g. AS8068 or ${B}IP${D} - e.g. $host_ip (domain host)\n"
echo -e -n "  ${B}>>${D}  "
read target_as
echo ''
f_solidShort
echo -e "== $target_as AUTONOMOUS SYSTEM INFORMATION (via hackertarget.com) == \n\n" >> $out
echo ''
curl -s --max-time 4 https://api.hackertarget.com/aslookup/?q=$target_as | tee -a $out
echo ''
f_solidLong
f_removeDir
;;
21)
#************** 21) reverse IP lookup (submenu domain) ********************
f_makeNewDir
f_solidLong
f_solidLineText
echo -e "\n${B}Reverse IP Lookup (via hackertarget.com)${D}\n\n"
echo -e "== REVERSE IP LOOKUP (via hackertarget.com) ==\n\n" >> $out
curl -s https://api.hackertarget.com/reverseiplookup/?q=$host_ip | tee -a $out
f_solidLong
f_removeDir
;;
22)
#************** 22) zone transfer check (submenu domain) ********************
f_makeNewDir
f_solidLong
f_solidLineText
echo -e "\n${B}$target Zone Transfer Check${D}\n\n"
echo -e "== $target ZONE TRANSFER CHECK ==\n" >> $out
f_zoneTransfer | tee -a $out
f_solidLong
f_removeDir
;;
23)
#************** 23) server response times & tracepath (submenu domain) ********************
f_makeNewDir
f_solidLong
f_solidLineText
echo -e "\n${B}Server Status & Response Times${D}\n"
echo -e " == SERVER STATUS == \n" >> $out
f_connCheck
echo -e "\n\n${B}Host IP Addresses${D}\n"
f_aRecord
echo -e "\n\n${B}Server Response Times${D}\n"
echo -e "\n\n == SERVER RESPONSE TIMES == \n" >> $out
f_resTime | tee -a $out
f_tracePath
f_solidLong
f_removeDir
;;
31)
#******************* 31) target - dns & whois reverse lookup (submenu IP)  **********************
f_makeNewDir
f_solidLong
f_solidLineText
echo -e "\n${B}PTR Record${D}\n"
echo -e "== PTR RECORD ==\n" >> $out
host -t A $target | cut -d ' ' -f 3- | rev | cut -d '.' -f 2- | rev | tee -a $out
whois $target > $tempdir/rev-whois.txt
echo -e "\n\n${B}$target reverse whois Summary${D}\n\n"
echo -e "\n\n== $target REVERSE WHOIS SUMMARY == \n\n" >> $out
f_drwho
f_solidLong
f_removeDir
;;
32)
#******************* 32) headers summary & website title (submenu IP)  **********************
f_makeNewDir
f_solidLong
f_solidLineText
f_connCheck
echo -e "\n" | tee -a $out
f_headers
echo -e "\n\n${B}PTR Record${D}\n"
echo -e "\n\n== PTR RECORD ==\n" >> $out
host -t A $target | cut -d ' ' -f 3- | rev | cut -d '.' -f 2- | rev | tee -a $out
echo -e "\n\n${B}Website Title${D}\n"
echo -e "\n\n== WEBSITE TITLE ==\n" >> $out
f_website_Title | tee -a $out
f_solidLong
f_removeDir
;;
33)
#***********************  33) certificate information  & -file (submenu IP) **************************
f_makeNewDir
f_solidLong
f_solidLineText
timeout 3 openssl s_client -connect $target:443 -brief 2>$tempdir/ssl_sum2.txt
echo | timeout 3 openssl s_client -connect $target:443 2>>$tempdir/status.txt -status >> $tempdir/status.txt
echo | timeout 3 openssl s_client -connect $target:443 2>>$tempdir/ssl_sum2.txt | openssl x509 -text -enddate >> $tempdir/ssl_sum2.txt
cat $tempdir/ssl_sum2.txt | tr -d '"' | sed 's/AES_/AES-/g' | sed 's/ = /: /g' | sed 's/_/ - /g' | tr -d '(' | tr -d ')' |
sed 's/^ *//' > $tempdir/ssl.txt
echo -e "\n${B}Certificate Status & SSL/TLS Information${D}\n\n"
echo -e "== CERTIFICATE STATUS & SSL/TLS INFORMATION ==\n\n" >> $out
f_certInfo | tee -a $out
echo -e "\n\n\n${B}Certificate Chain (depth:2-1-0)${D}\n"
echo -e "\n\n\n== CERTIFICATE CHAIN (depth:2-1-0) == \n\n" >> $out
f_certChain | tee -a $out
echo -e "\n"
f_Dashes_long
echo ''
echo -e -n "Display Certificates & Public Key?  ${BDim}yes [y] | no [any other key]${D}  "
read answer
echo ''
f_Dashes_long
echo ''
if [ $answer = "y" ]
then
    f_showCerts | tee $HOME/$target.certificate.txt
fi
f_solidLong
f_removeDir
;;
34)
#******************* 34) target IP geolocation via ip-api.co (submenu IP)  **********************
f_makeNewDir
f_solidLong
f_solidLineText
echo -e "${B}$target geolocation (via ip-api.co)${D}\n\n"
echo -e "== $target GEOLOCATION (via ip-api.co) ==\n\n" >> $out
address=`echo $target`
f_geoIP | tee -a $out
f_solidLong
f_removeDir
;;
35)
#******************* 35) HTTP headers / link dump (submenu IP)  **********************
f_solidLong
f_filedumpIP
f_solidShort
;;
36)
#******************* 36) address block reverse host search (subemnu IP)  **********************
f_makeNewDir
f_solidLong
f_solidLineText
prefx=`echo $target | rev | cut -d '.' -f 2- | rev`
echo -e "\n${B}$target Address Block Reverse Host Search${D}\n\n"
echo -e "== $target ADDRESS BLOCK REVERSE HOST SEARCH ==\n\n" >> $out
f_hostSearch | tee -a $out
f_solidLong
f_removeDir
;;
37)
#************** 37) AS Information (submenu IP) ********************
f_makeNewDir
f_solidLong
f_solidLineText
echo -e "${B}Autonomous System Information (via hackertarget.com)${D}\n\n"
echo -e "== AUTONOMOUS SYSTEM INFORMATION (via hackertarget.com)== \n\n" >> $out
curl -s --max-time 4 https://api.hackertarget.com/aslookup/?q=$target | tee -a $out
echo ''
f_solidLong
f_removeDir
;;
38)
#************** 38) reverse IP lookup (submenu IP) ********************
f_makeNewDir
f_solidLong
f_solidLineText
echo -e "\n${B}Reverse IP Lookup (via hackertarget.com)${D}\n\n"
echo -e "== REVERSE IP LOOKUP ==\n\n" >> $out
curl -s https://api.hackertarget.com/reverseiplookup/?q=$target | tee -a $out
f_solidLong
f_removeDir
;;
39)
#************** 39) server response times & tracepath (submenu IP) ********************
f_makeNewDir
f_solidLong
f_solidLineText
echo -e "\n${B}Server Response Times${D}"
echo -e "== SERVER RESPONSE TIMES ==\n" >> $out
f_connCheck
echo ''
f_resTime | tee -a $out
f_tracePath
f_solidLong
f_removeDir
;;
41)
#************** 41) primary name server reverse whois summary (submenu domain) ********************
f_makeNewDir
f_solidLong
f_solidLineText
soa_ip=`host -t A $soa_url | cut -d ' ' -f 4-`
whois $soa_ip > $tempdir/rev-whois.txt
echo -e "\n${B}Primary Name Server reverse whois Summary\n"
echo -e " ${BDim}$soa_url - $soa_ip${D}\n\n"
echo -e "== PRIMARY NAME SERVER REVERSE WHOIS SUMMARY ==\n" >> $out
echo -e " $soa_url - $soa_ip\n\n" >> $out
f_drwho
echo ''
f_solidShort
f_whoisOptions
f_solidLong
f_removeDir
;;
42)
#************** 42) "first" mx server reverse whois summary (submenu domain) ********************
f_makeNewDir
f_solidLong
f_solidLineText
mx_first_url=`echo "$mx_url" | sort | head -1`
mx_first_ip=`host -t A $mx_first_url | cut -d ' ' -f 4- | sort | head -1`
whois $mx_first_ip > $tempdir/rev-whois.txt
echo -e "\n${B}\"First\" MX Record reverse whois Summary\n"
echo -e " ${BDim}$mx_first_url - $mx_first_ip${D}\n\n"
echo -e "== \"FIRST\" MX RECORD REVERSE WHOIS SUMMARY ==\n" >> $out
echo -e " $mx_first_url - $mx_first_ip\n\n" >> $out
f_drwho
echo -e "\n--------------------------------------" | tee -a $out
echo -e "The results shown are for the \nMX record that comes first in either \npriority or alphabetical order" |
tee -a $out
echo ''
f_solidShort
f_whoisOptions
f_solidLong
f_removeDir
;;
43)
#************** 43) whois lookup summary - custom input (submenu domain) ********************
f_makeNewDir
f_solidLong
f_solidLineText
echo -e "\n${B}whois Summmary - Custom Input${D}\n"
echo -e "  Set target ${B}DOMAIN${D} - e.g. example.com\n"
echo -e -n "  ${B}>>${D}  "
read domainname
f_solidLong
echo -e "\n== $domainname WHOIS SUMMARY ==\n\n" >> $out
whois $domainname > $tempdir/host-whois.txt
f_whoisRequest
echo ''
f_solidShort
f_whoisOptions
f_solidLong
f_removeDir
;;
44)
#************** 44) reverse whois lookup summary - custom input (submenu domain) ********************
f_makeNewDir
f_solidLong
f_solidLineText
echo -e "\n${B}Reverse whois Summary - Custom Input${D}\n"
echo -e "   \nSet target ${B}IP${D} - e.g. 45.33.32.156\n"
echo -e -n "  ${B}>>${D}  "
read address
f_solidLong
whois $address > $tempdir/rev-whois.txt
echo -e "\n${B}$address Reverse whois Summary${D} \n\n"
echo -e "\n== $address REVERSE WHOIS SUMMARY ==\n\n"  >> $out
f_drwho
echo ''
f_solidShort
f_whoisOptions
f_solidLong
f_removeDir
;;
53)
#******************* 53) HTTP headers (submenu IP)  **********************
f_makeNewDir
f_solidLong
f_solidLineText
echo -e "\n${B}HTTP Headers${D}\n\n"
echo -e "== HTTP HEADERS ==\n\n" >> $out
curl -s -I -L --max-time 4 $target | tee -a $out
echo ''
f_solidShort
f_filedumpIP
f_solidLong
f_removeDir
;;
54)
#******************* 54) link dump (submenu IP)  **********************
f_makeNewDir
f_solidLong
f_solidLineText
echo -e "\n${B}Link Dump${D}\n"
echo -e "== LINK DUMP ==\n" >> $out
f_linkDump
f_solidLong
f_removeDir
;;
61)
#************** 61) primary name server geolocation (submenu domain)  ********************
f_makeNewDir
f_solidLong
f_solidLineText
soa_ip=`host -t A $soa_url | cut -d ' ' -f 4-`
echo -e "\n${B}Primary Name Server Geolocation${D}\n"
echo -e " ${BDim}$soa_url - $soa_ip${D}\n"
echo -e "== PRIMARY NAME SERVER GEOLOCATION ==\n" >> $out
echo -e " $soa_url - $soa_ip\n\n" >> $out
address=`echo $soa_ip`
f_geoIP | tee -a $out
echo ''
f_solidShort
f_geoOptions
f_solidLong
f_removeDir
;;
62)
#************** 62) IP geolocation - custom input (submenu domain)  ********************
f_makeNewDir
f_solidLong
f_solidLineText
echo -e "\n${B}IP Geolocation - Custom Input${D}\n"
echo -e "   \nSet Target ${B}IP${D} - e.g. 45.33.32.156\n"
echo -e -n "  ${B}>>${D}  "
read address
f_solidLong
echo -e "== $address IP GEOLOCATION ==\n"  >> $out
f_geoIP | tee -a $out
echo ''
f_solidLong
f_removeDir
;;
71)
#************** 71) HTTP headers (submenu domain)  ********************
f_makeNewDir
f_solidLong
f_solidLineText
echo -e "\n${B}HTTP Headers${D}\n"
echo -e "== HTTP HEADERS ==\n" >> $out
curl -s -I -L --max-time 4 $target | tee -a $out
echo ''
f_solidShort
f_filedumpOptions
f_solidLong
f_removeDir
;;
72)
#************** 72) robots.txt (submenu domain) ********************
f_makeNewDir
f_solidLong
f_solidLineText
echo -e "\n${B}robots.txt${D}\n"
echo -e "== robots.txt ==\n" >> $out
curl -s -L --max-time 4 $target/robots.txt | tee -a $out
echo ''
f_solidShort
f_filedumpOptions
f_solidLong
f_removeDir
;;
73)
#************** 73) link dump (submenu domain)  ********************
f_makeNewDir
f_solidLong
f_solidLineText
echo -e "\n${B}Link Dump${D}\n"
echo -e "== LINK DUMP ==\n" >> $out
f_linkDump
f_solidLong
f_removeDir
;;
81)
#************** 81) domain host address block reverse host search (submenu domain)  ********************
f_makeNewDir
f_solidLong
f_solidLineText
prefx=`dig x +short $target | rev | cut -d '.' -f 2- | rev`
echo -e "\n${B}$host_ip Address Block Reverse Host Search ${D}\n\n"
echo -e "== $host_ip ADDRESS BLOCK REVERSE HOST SEARCH == \n\n" >> $out
f_hostSearch | tee -a $out
echo ''
f_solidShort
f_optionsHostSearch
f_solidLong
f_removeDir
;;
82)
#************** 82) address block reverse host search - custom input (submenu domain)  ********************
f_makeNewDir
f_solidLong
f_getPrefixes
echo -e "\n${B}Reverse Host Search - Custom Input${D}\n"
echo -e "${BDim}Host prefix:  $host_prefix ${D}"
echo -e "\n\nFor further enumeration you may want to pick one of the following IPv4-prefixes:"
echo -e "\n\nIPv4 Prefixes (MX- Records):\n"
cat $tempdir/mx_prefixes.txt | sort | uniq
echo -e "\n\nIPv4 Prefixes (NS- Records):\n"
cat $tempdir/ns_prefixes.txt | sort | uniq
echo -e "\n"
echo -e -n "Proceed? ${BDim} [y] yes | no [any other key]${D}   "
    read answer
    if [ $answer = "y" ]
        then
echo -e "\nPlease enter a network prefix:\n "
echo -e -n "  ${B}>>${D}  "
read prefx
echo ''
f_solidLineText
echo -e "== $prefx ADDRESS BLOCK REVERSE HOST SEARCH ==\n\n" >> $out
f_hostSearch | tee -a $out
fi
f_solidLong
f_removeDir
;;
91)
#************** 91) subdomain enumeration (submenu domain)  ********************
f_makeNewDir
f_solidLong
f_solidLineText
echo -e "\n${B}$target Subdomains (via hackertarget.com) ${D}\n\n"
echo -e "== $target SUBDOMAINS (via hackertarget.com) == \n\n" >> $out
curl -s --max-time 4 https://api.hackertarget.com/hostsearch/?q=$target | sed 's/,/ -  /g' | tee -a $out
echo ''
f_solidShort
f_subEnumOptions
f_solidLong
f_removeDir
;;
92)
#************** 92) subdomain enumeration (via crt.sh - API) (submenu domain)  ********************
f_makeNewDir
f_solidLong
f_solidLineText
echo -e "\n${B}$target Subdomains (via crt.sh)${D}\n\n"
echo -e "== $target SUBDOMAINS (via crt.sh) == \n\n" >> $out
curl -s --max-time 4 https://crt.sh/?q=$target > $tempdir/crt.txt
cat $tempdir/crt.txt | grep $target | sed 's/<TD>//' | sed 's/<\/TD>//' | sed 's/<BR>/\n/g' | sed 's/^ *//' |
sed '/<TD/d' | sed '/<\/A>/d' | sed '/<TITLE>/d' | sed '/<TH/d'  | sed '/@/d' | sort | uniq | tee -a $out
f_solidLong
f_removeDir
;;
#******************* 0) exit  **********************
0)
f_makeNewDir
f_solidLineText
echo -e "  END OF FILE \n\n" >> $out
echo -e "\n${B}----------------------------- Done ------------------------------\n"
echo -e "                  ${BDim}Author - Thomas Wy, August 2020${D}\n\n"
f_removeDir
break
;;
esac
done

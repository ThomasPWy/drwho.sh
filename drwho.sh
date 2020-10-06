#!/bin/bash
#************ Variables - colors & temp. directory ***********
B='\033[1;34m'
BDim='\033[0;34m'
D='\033[0m'
GREY='\033[1;30m'
GR='\033[1;32m'
R='\033[1;31m'
tempdir="$PWD/drwho_temp"
#************* startmenu with global options  ******************
function f_startMenu {
    echo ''
    echo "   a)  SET TARGET"
    echo "   s)  OPTIONS (IPv4)"
    echo "   d)  OPTIONS (DOMAINS)"
    echo "   p)  PORT SCAN & PING SWEEP"
    echo "   q)  QUIT"
}
#************** drwho - banner *************

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
    echo -e "${GREY}____________________________________________________________________${D}"
}
function f_solidLineText {
    echo -e "\n___________________________________________________________________________\n"
}
function f_dashedGrey {
     echo -e "${GREY}----------------------------------------------------------------------${D}"
}
function f_solidShort {
    echo -e "${BDim}      ____${D}\n"
}
#************ connectivity check (curl) *************
function f_connCheck {
error_code=6
curl -sf "${target}" > /dev/null
if [ $? = ${error_code} ];then
echo -e "${R} CONNECTION: FAILURE${D}\n"
echo -e "\n\n CONNECTION: FAILURE\n" >> $out/$target.txt
continue
else
echo -e "\n${B}STATUS:${D}  ${GR}ONLINE${D}"
echo -e "$target STATUS:  ONLINE \n" >> $out/$target.txt
fi
}

#*********************** dns records  ***************************
function f_aRecord {
host -t A $target | cut -d ' ' -f 4-
echo -e "---------------"
host -t AAAA $target | cut -d ' ' -f 3-
}
function f_mxIPv4 {
            for i in $(echo $mx_url)
            do
                echo | host -t A $i | sed -e 's/has/\n/' | sed 's/address/   /' | tee -a $out/$target.txt
            done
}
function f_nsIPv4 {
            for i in $(echo $ns_url)
            do
             echo | host -t A $i | sed -e 's/has/\n/' | sed 's/address/   /' | tee -a $out/$target.txt
           done
}
function f_mxIPv6 {
        for i in $(echo $mx_url)
        do
            echo | host -t AAAA $i | sed -e 's/has/ \n/'  | sed 's/IPv6//' | sed 's/address/  /' | sed 's/no/  no/' | tee -a $out/$target.txt
        done
}
function f_nsIPv6 {
        for i in $(echo $ns_url)
        do
            echo | host -t AAAA $i | sed -e 's/has/ \n/' | sed 's/IPv6//' | sed 's/address/   /' | sed 's/no/  no/' | tee -a $out/$target.txt
        done
}
#************ certificate status & algorithms *************
function f_certInfo {
subject=`cat $tempdir/ssl.txt | grep -m 1 -w 'Subject:' | sed 's/, Inc/ Inc/' | sed 's/,/\n/g' | sed 's/Subject://g'`
subject_org=`echo "$subject" | grep -w 'O:' | sed 's/^ *//' | sed 's/O:/  Org: /'`
subject_location=`echo "$subject" | grep -w 'L:' | tr -d ' '  | sed 's/L:/\/ /' | sed 's/^ *//'`
subject_country=`echo "$subject" | grep -w 'C:' | tr -d ' ' | sed 's/C:/\/ /'`
subject_name=`echo "$subject" | grep -w 'CN:' | sed 's/CN://' | sed 's/^ *//'`
issuer=`cat $tempdir/ssl.txt | grep -m 1 -w 'Issuer:' | sed 's/, Inc//' | sed 's/,/\n/g'| sed 's/Issuer://g'`
issuer_org=`echo "$issuer" | grep -w 'O:' | sed 's/^ *//' | sed 's/O:/Org: /'`
issuer_location=`echo "$issuer" | grep -w 'L:' | tr -d ' '  | sed 's/L:/\/ /' | sed 's/^ *//'`
issuer_country=`echo "$issuer" | grep -w 'C:' | tr -d ' ' | sed 's/C:/\/ /'`
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
echo -e  "\nSubject:    $subject_name $subject_org $subject_country"
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
subject=`cat $tempdir/ssl.txt | grep -m 1 -w 'Subject:' | sed 's/, Inc/ Inc/' | sed 's/,/\n/g' | sed 's/Subject://g'`
subject_org=`echo "$subject" | grep -w 'O:' | sed 's/^ *//' | sed 's/O:/, /'`
subject_location=`echo "$subject" | grep -w 'L:' | tr -d ' '  | sed 's/L:/\/ /' | sed 's/^ *//'`
subject_country=`echo "$subject" | grep -w 'C:' | tr -d ' ' | sed 's/C:/\/ /'`
subject_name=`echo "$subject" | grep -w 'CN:' | sed 's/CN://' | sed 's/^ *//'`
issuer=`cat $tempdir/ssl.txt | grep -m 1 -w 'Issuer:' | sed 's/, Inc//' | sed 's/,/\n/g'| sed 's/Issuer://g'`
issuer_org=`echo "$issuer" | grep -w 'O:' | sed 's/^ *//' | sed 's/O:/, /'`
issuer_location=`echo "$issuer" | grep -w 'L:' | tr -d ' '  | sed 's/L:/\/ /' | sed 's/^ *//'`
issuer_country=`echo "$issuer" | grep -w 'C:' | tr -d ' ' | sed 's/C:/\/ /'`
issuer_name=`echo "$issuer" | grep -w 'CN:' | sed 's/CN://' | sed 's/^ *//'`
verification=`cat $tempdir/ssl.txt | grep -m 1 -w 'Verification:' | sed 's/Verification://' | sed 's/^ *//'`
echo -e -n "Expires:     "
cat $tempdir/ssl.txt | grep -i -m 1 'after' | cut -d ' ' -f 4-
echo -e  "\nSubject:     $subject_name $subject_org $subject_country"
echo -e  "\nverify:      $verification"
echo -e  "\nIssuer:      $issuer_name $issuer_org $issuer_country"
}
#************************** dump certificates *********************************
function f_showCerts {
echo -e "\n\n=== $target CERTIFICATES ===\n"
echo -e "DATE:  $(date) \n\n"
timeout 3 openssl s_client -connect $target:443 -showcerts
echo -e "\n________________________________________________________________\n"
echo -e "$target PUBLIC KEY\n"
timeout 3 openssl s_client -connect $target:443 2>>/dev/null | openssl x509 -pubkey -noout | sed '/---/d'
}
#************************** HTTP- headers summary *********************************
function f_headers {
    curl -s -I -L -k --max-time 3 $target > $tempdir/headers.txt
    cat $tempdir/headers.txt | sed '/[Hh][Ii][Tt]/d' | sed '/[Mm][Ii][Ss][Ss]/d' | sed '/bsig:/d' | sed '/bid:/d' |
    sed '/[Dd][Aa][Tt][Ee]:/d' | sed '/{/d' | sed '/}/d' | sed '/[Rr]eport*/d' | sed '/[Vv]ary/d' | sed '/[Cc]ache-[Cc]ontrol/d' | 
    sed '/[Ee]-[Tt][Aa][Gg]:/d' | sed '/[Ee][Tt][A#a][Gg]/d' | sed '/[Aa]ge:/d' | sed '/[Cc]ontent-[Ll]ength:/d' | 
    sed '/brequestid:/d' | sed '/[Ss]et-[Cc]ookie/d' | sed '/[Cc]ontent-[Ss]ecurity-[Pp]olicy:/d' | sed '/X-UA-Compatible/d' |
    sed '/x-ua-compatible/d' |sed '/[Aa]ccept-[Rr]anges/d' | sed '/[Xx]-[Dd]ownload-[Oo]ptions/d' | sed '/[Xx]-[Tt]imer/d' | 
    sed '/max_age/d' | sed '/[Ff]eature-[Pp]olicy/d' | sed '/[Xx]-[Cc]ache-*/d' | sed '/x-.*-edge-.*/d' | sed '/[Xx]-[Ee]dge-.*/d' | 
    sed '/[Ee]xpect-[Cc][Tt]:/d' | sed '/[Ll]ast-[Mm]odified:/d'  | sed '/NEL:/d' | sed '/-src/d' | sed '/[Xx]-[Vv]cs/d' | 
    sed '/[Xx]-[Vv][Cc][Ss]-*/d' | sed '/[Vv]ia:/d' | sed '/X-.*-Request-Id:/d' | sed '/[Xx]-[Rr]equest-[Ii]d:/d' | sed '/[Ee]xpires:/d' | 
    sed '/[Xx]-[Ss]erved-[Bb]y:/d' | sed '/req-svc-chain:/d' | sed '/[Rr]etry-[Aa]fter:/d' | sed '/[Kk]eep-[Aa]live:/d' | sed '/href=*/d' | 
    sed '/[Ll]ink:/d' | sed '/[Cc]onnection:/d' | sed '/[Aa]ccess-[Cc]ontrol-[Aa]llow-[Oo]rigin:/d' | sed '/[Xx]-[Rr]untime:/d' | 
    sed '/[Xx]-[Dd]ispatcher:/d' | sed '/[Pp]ragma:/d' | sed '/[Xx]-[Rr]ule:/d' | sed '/[Xx]-[Pp]ermitted-[Cc]ross-[Dd]omain-[Pp]olicies:/d' | 
    sed '/[Rr]eferrer-[Pp]olicy:/d' | sed '/[Xx]-[Cc]loud-[Tt]race-[Cc]ontext:/d' | sed '/[Xx]-[Vv]iew-[Nn]ame:/d' | sed '/[Tt]ransfer-[Ee]ncoding:/d' |
    sed '/[Xx]-ac:/d' | sed '/[Xx]-[Ii]nstrumentation:/d' | sed '/x-server-lifecycle-phase:/d' | sed '/[Xx]-[Kk]raken-[Ll]oop-[Nn]ame:/d' |
    sed '/[Aa]ccept-[Cc]h-[Ll]ifetime:/d' | sed '/[Xx]-[Ee]nvoy-[Uu]pstream-*/d' | sed '/[Cc]ontent-[Tt]ype/d' | sed '/[Aa]ccept-[Cc]h/d' |
    sed '/[Xx]-[Ll]b-[Nn]ocache:/d' | sed '/[Xx]-[Ss]erver-[Gg]enerated:/d' | fmt -w 80 -s | tee -a $out/$target.txt
}

#************************** website title *********************************
function f_website_Title {
if ! type lynx &> /dev/null; then
              curl -s -k -L --max-time 4 $target > $tempdir/target_src.txt
              cat $tempdir/target_src.txt | grep -o "<title>[^<]*" | tail -c +8 | fmt -w 80 -s 
         else
              lynx -accept_all_cookies -crawl -dump $target | grep TITLE | sed 's/THE_TITLE://' | sed 's/^ *//' | tee -a $out/$target.txt
         fi
}
#*************************** content of <meta name=description...> tag *********************************
function f_targetDescription {
    curl -s -k -L --max-time 4 $target > $tempdir/target_src.txt
    cat $tempdir/target_src.txt | grep -w -A 1 "meta" | sed 's/^ *//' >> $tempdir/meta.txt
    cat $tempdir/meta.txt | tr -d '"' | tr -d '<' | tr -d '>' | tr -d '/' |sed '/meta name=description content=/!d' |
    sed 's/meta/\nmeta/g' > $tempdir/content.txt
    cat $tempdir/content.txt | sed '/meta name=description content=/!d' | sed 's/meta name=description content=//' |
    sed 's/&#039;s/s/' | sed 's/link//' | sed 's/meta name=twitter:card//' | sed 's/rel=canonical//' | sed 's/href/\nhref/' |
    sed 's/meta property=og:type//' | sed 's/\!--/\n\!--/' | sed '/\!--/d' | sed '$!N; /^\(.*\)\n\1$/!P; D' | sed 's/^ *//' |
    sed 's/title/\ntitle/' | sed '/name=theme-color/d' | sed '/href=*/d' | sed 's/&amp;/\&/' | fmt -w 70 -s | tee -a $out/$target.txt
}
#********************* use lynx to scrape target website for social media & contact hyperlinks *****
function f_socialLinks {
if ! type lynx &> /dev/null; then
        echo "Please install lynx"; else
lynx -accept_all_cookies -dump -listonly -nonumbers www.$target > $tempdir/socialmedia.txt
cat $tempdir/socialmedia.txt | grep -F -econtact -ediscord -ekontakt -econtatto -eimpressum -eetsy -efacebook -egithub -einstagram -elinkedin -epinterest -ereddit -esnapchat -etwitch -etwitter -exing -eyoutube -emailto | sed '/sport/d' |  sed '/program/d' | sed 's/mailto:/\nmailto:/' | sed 's/mailto://' | sort | 
uniq | tee -a $out/$target.txt
fi
}
#********************* use lynx to scrape target website for hyperlinks *****
function f_linkDump {
if ! type lynx &> /dev/null; then
        echo "Please install lynx"
    else
        lynx -accept_all_cookies -dump -listonly www.$target | tee -a $out/$target.txt
    fi
    echo ''
}
#************************ AS information *****************************
function f_pwhois {
    grep -w "IP:"          $tempdir/pwhois.txt | sed 's/IP:/IP:             /'
    grep -w "Prefix:"      $tempdir/pwhois.txt | sed 's/Prefix:/Prefix:         /'
    grep -w "AS-Path:"     $tempdir/pwhois.txt | sed 's/AS-Path:/AS-Path:        /'
    echo ''
    grep -w "Origin-AS:"   $tempdir/pwhois.txt | sed 's/Origin-AS:/Origin-AS       /'
    echo ''
    grep -w "Org-Name:"    $tempdir/pwhois.txt | sed 's/Org-Name:/Org-Name:       /' | sed 's/AS-Org-Name:   /AS-Org-Name:/'
    grep -w "Net-Name:"    $tempdir/pwhois.txt | sed 's/Net-Name:/Net-Name:       /'
    grep -w "Latitude:"    $tempdir/pwhois.txt | sed 's/Latitude:/\nLatitude:       /'
    grep -w "Longitude:"   $tempdir/pwhois.txt | sed 's/Longitude:/Longitude:      /'
    grep -w "City:"        $tempdir/pwhois.txt | sed 's/City:/City:           /' 
    grep -w "Region:"      $tempdir/pwhois.txt | sed 's/Region:/Region:         /'
    grep -w "Country:"     $tempdir/pwhois.txt | sed 's/Country:/Country:        /'
    grep -w "Country-Code:" $tempdir/pwhois.txt | sed 's/Country-Code:/CountryCode:    /'
}
function f_asContact {
abuse_mailbox=`grep -m1 'abuse-mailbox' $tempdir/rev-whois.txt | sed 's/abuse-mailbox://' | sed 's/^ *//'`
org_email=`grep 'OrgAbuseEmail' $tempdir/rev-whois.txt | sed 's/OrgAbuseEmail://' | sed 's/^ *//'`
echo "Contact:        $abuse_mailbox$org_email"
echo ''
}
#************************* geolocation data *********************************
function f_geoIP {
    curl -s https://ipapi.co/$address/json | tr -d '{' | tr -d '}' | tr -d ',' | tr -d ' "' | sed -r '/^\s*$/d' |
    fmt -w 70 -s > $tempdir/geo.txt
    ip=`cat $tempdir/geo.txt | head -1 | cut -d ':' -f 2 | sed 's/^ *//'`
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
        echo "IP:             $ip"
        echo ''
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
    sed 's/Technical/\nTechnical/' | fmt -w 80 -s | tee -a $out/$target.txt
}
function f_drwho {
cat $tempdir/rev-whois.txt | sed '/^#/d' | sed '/^%/d'  | sed '/inject:/d' | sed '/\*/d' | sed '/Parent:/d' |
sed '/NetType:/d' | sed '/OriginAS:/d' | sed '/tech-c*/d' | sed '/Comment:/d' | sed -r '/^\s*$/d' | sed '/Ref:/d' |
sed '/ResourceLink:/d' | sed '/OrgAbuseRef:/d' | sed '/RTech*/d' | sed '/please/d' | sed "/^[[:space:]]*$/d" | 
sed 's/role/\nrole/' | sed 's/person/\nperson/' | sed 's/route/\nroute/' | sed 's/OrgAbuseHandle:/\nOrgAbuseHandle:'/ | 
sed 's/OrgTechHandle:/\nOrgTechHandle:/' | tee -a $out/$target.txt
}
#************************* server response times *********************************
function f_resTime {
  curl $target -s -L -o /dev/null -w \
"
TOTAL:            %{time_total}

connect:          %{time_connect}
appconnect:       %{time_appconnect}
start_transfer:   %{time_starttransfer}
pretransfer:      %{time_pretransfer}

dns_lookup:       %{time_namelookup}
redirects:        %{time_redirect}

IP:               %{remote_ip}
URL:              %{url_effective}
HTTP Code:        %{response_code}
Redirects:        %{num_redirects}
"
}
#**************************** optionally run trace path *********************************
function f_tracePath  {
    echo -e "\n"
    echo -e -n "Run tracepath?  ${B}[y]${D} | ${B}[n]${D}  "
    read answer
    if [ $answer = "y" ]
        then
        echo ''
        echo -e -n "Choose mode:    ${B}[4]${D} IPv4 | ${B}[6]${D} IPv6 | ${B}[b]${D} both  "
        read IPvChoice
        if [ $IPvChoice = "4" ]
           then
        echo -e "\n\n${B}Tracepath Results (IPv4)${D}\n\n"
        echo -e "\n\n == TRACEPATH RESULTS (IPv4) == \n\n" >> $out/$target.txt
        tracepath -4 -b -m 22 $target | tee -a $out/$target.txt
        elif [ $IPvChoice = "6" ]
           then
        echo -e "\n\n${B}Tracepath Results (IPv6)${D}\n\n"
        echo -e "\n\n == TRACEPATH RESULTS (IPv6) == \n\n" >> $out/$target.txt
        tracepath -6 -b -m 22 $target | tee -a $out/$target.txt
        elif [ $IPvChoice = "b" ]
           then
        echo -e "\n\n == TRACEPATH RESULTS (IPv4) == \n\n" >> $out/$target.txt
        echo -e "\n\n${B}Tracepath Results (IPv4)${D}\n\n"
        tracepath -4 -b -m 22 $target | tee -a $out/$target.txt
        echo -e "\n\n${B}Tracepath Results (IPv6)${D}\n\n"
        echo -e "\n\n == TRACEPATH RESULTS (IPv6) == \n\n" >> $out/$target.txt
        tracepath -6 -b -m 22 $target | tee -a $out/$target.txt
        else
        echo -e "\n${R}Please choose IPv4 or IPv6 mode${D}\n"
        fi
    else
      echo ''
    fi
}
#**************************** checking if server allows unauthorized zone transfers  ********
function f_zoneTransfer {
    dig ns +short $target | rev | cut -c  2- | rev > $tempdir/ns.txt
    for i in $(cat $tempdir/ns.txt); do
        dig axfr @${i} $target 
    done
}
#**************************** search for hosts in /24 address block via reverse dns lookup *************
function f_getPrefixes {
    mx_url=`dig mx +short $target | rev | cut -c 2- | rev | cut -d " " -f 2-`
    ns_url=`dig ns +short $target | rev | cut -c 2- | rev | cut -d " " -f 2-`
    txt_ipv4=`dig txt +short $target | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'`  
        for a in $(echo $mx_url); do
            dig +short $a | rev | cut -d '.' -f 2- | rev >> $tempdir/mx_prefixes.txt
        done
        for b in $(echo $ns_url); do
            dig +short $b | rev | cut -d '.' -f 2- | rev >> $tempdir/ns_prefixes.txt
        done
        echo "$txt_ipv4" | rev | cut -d '.' -f 2- | rev >> $tempdir/txt_prefixes.txt
}
function f_hostSearch {
    for i in `seq 1 255` ; do sublist="$sublist ${prefx}.$i" ; done
    for i in $sublist ; do
        ptr=`host $i | cut -d ' ' -f 5` 
        echo "$i - $ptr" | sed '/NXDOMAIN/d' 
    done
    echo ''
}
#*********** banner for output file *************
function f_textfileBanner {
    echo -e "    -------------"                       
    echo -e "       Drwho"                            
    echo -e "    -------------"                       
    echo -e "\nAuthor - Thomas Wy, Sept 2020\n"     
    echo -e "https://github.com/ThomasPWy/drwho.sh \n" 
    echo -e "TARGET:  $target  ($(dig +short $target))" 
    echo -e "DATE:    $(date) \n"
    f_solidLineText                       
}
#*********** menus *************
function f_menuDomain {
    f_dashedGrey 
    echo -e "\n ${B}  >> Target: $target - $target_ip ${D}\n"
    echo -e "  ${B} 1)${D}  website overview          ${B}11)${D}  certificates"  
    echo -e "  ${B} 2)${D}  DNS records               ${B}12)${D}  AS Info" 
    echo -e "  ${B} 3)${D}  resp.times,tracepath      ${B}13)${D}  IP geolocation (ext.API)"      
    echo -e "  ${B} 4)${D}  shared NS (ext.API)       ${B}14)${D}  whois"
    echo -e "  ${B} 5)${D}  subdomains (ext.API)      ${B}15)${D}  IP address block host search" 
    echo -e "  ${B} 6)${D}  zone transfer             ${B}16)${D}  reverse IP lookup (ext.API)"
    echo -e "  ${B} 0)${D}  MAIN MENU                 ${B}17)${D}  headers, robots.txt, link dump"  
} 
function f_menuIP {
    f_dashedGrey 
    echo -e "\n ${B}  >> Target: $target${D}\n"
    echo -e "  ${B}11)${D}  certificates              ${B}15)${D}  IP address block host search"            
    echo -e "  ${B}12)${D}  AS Info                   ${B}16)${D}  reverse IP lookup (ext.API)"
    echo -e "  ${B}13)${D}  IP geolocation (ext.API)  ${B}17)${D}  headers, robots.txt, link dump" 
    echo -e "  ${B}14)${D}  whois options             ${B}21)${D}  resolve ip" 
    echo -e "  ${B} 0)${D}  MAIN MENU                 ${B}22)${D}  website overview"  
    echo -e "  ${B} q)${D}  QUIT                      ${B}23)${D}  resp.times,tracepath"                                  
}
function f_optionsAS {                           
    echo -e "\n  ${B}122)${D}  $target AS Information (whois.pwhois.org lookup)"        
    echo -e "  ${B}123)${D}  custom IP AS Information (whois.pwhois.org lookup)"  
}
function f_geoOptions { 
    echo -e "\n  ${B}31)${D}  $target geolocation (via ipapi.co)"    
    echo -e "  ${B}32)${D}  custom IP/domain geolocation (via ipapi.co)"                       
}
function f_optionsWhois {                           
    echo -e "\n  ${B}41)${D}  $target whois & reverse whois lookup"        
    echo -e "  ${B}42)${D}  custom IP/domain whois & reverse whois lookup"    
}
function f_optionsHostSearch {                           
    echo -e "\n  ${B}51)${D}  $target IPv4 address block host search"        
    echo -e "  ${B}52)${D}  custom IPv4 address block host search"   
}
function f_optionsNMAP {
    echo -e "\n  ${B}pp)${D}  nmap ping sweep"  
    echo -e "  ${B}pt)${D}  nmap scan via hackertarget.com"
}
function f_options_Dump {
    echo -e "\n  ${B}71)${D}  HTTP headers"        
    echo -e "  ${B}72)${D}  robots.txt" 
    echo -e "  ${B}73)${D}  link dump" 
}
function f_Menu {
    if [[ $target =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        f_menuIP ; else
        f_menuDomain
    fi
}

#***************************** main program loop *****************************
while true
do
echo ''
echo -e -n "   ${B}?${D}  "
read choice
case $choice in
0)
f_startMenu
;;
a)
#************** SET TARGET DOMAIN / IP  ********************
f_makeNewDir
f_dashedGrey 
echo ''
echo -e " Set Target ${B}DOMAIN${D} or ${B}IP${D}\n"
echo -e -n "  ${B}>>${D}  "
read target
echo ''
echo -e -n " Save output? ${B}[y]${D} | ${B}[n]${D} "
read answer
if [ $answer = "y" ] ; then
    echo -e -n "\n Path:  HOME/${B}dir_name >>${D} " ; read dirname
    mkdir $HOME/$dirname
    out="$HOME/$dirname"
else
    out="$tempdir"
    echo ''
fi
if [[ $target =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    target_ip=`echo $target`
    target_prefix=`echo $target | rev | cut -d '.' -f 2- | rev`
    f_menuIP
else
    target_ip=`host -t A $target | head -1 | cut -d " " -f 4`
    target_prefix=`echo $target_ip | rev | cut -d '.' -f 2- | rev`
    mx_url=`dig mx +short $target | rev | cut -c 2- | rev | cut -d " " -f 2-`
    ns_url=`dig ns +short $target | rev | cut -c 2- | rev`
    soa_url=`dig soa +short $target | cut -d ' ' -f 1 | rev | cut -c 2- | rev`
    f_menuDomain
fi
f_textfileBanner >> $out/$target.txt
;;
s) 
#*********** s), d) SUBMENUS For IP & DOMAIN OPTIONS *********
f_menuIP
;;
d)
f_menuDomain
;;
p)
f_dashedGrey 
echo -e "\n${B}IPv4 Routes ${D}\n"
ip -4 route | sed 's/default/DEFAULT/'
echo -e "\n${B}Current Network:${D}  $(ip -4 route | sed 's/default/DEFAULT/' | tail -1 | cut -d ' ' -f 1) \n" 
f_optionsNMAP
;;
1)
#************** 1) TARGET DOMAIN WEBSITE OVERVIEW  ********************
f_makeNewDir ; f_dashedGrey
f_connCheck
echo -e "\n" | tee -a $out/$target.txt
f_headers
echo -e "\n${B}Host IP Addresses${D}\n"
echo -e "\n\n == HOST IP ADDRESSES ==\n\n" >> $out/$target.txt
f_aRecord | tee -a $out/$target.txt
f_solidLong ; f_solidLineText >> $out/$target.txt
echo -e "${B}\nWebsite Title${D}\n"
echo -e "\n == WEBSITE TITLE ==\n" >> $out/$target.txt
f_website_Title 
echo ''
f_solidLong ; f_solidLineText  >> $out/$target.txt
echo -e "\n${B}$target Geolocation (ipapi.co)${D}\n"
echo -e " == $target IP GEOLOCATION (via ipapi.co) ==\n\n"  >> $out/$target.txt
address=`echo $target_ip`
f_geoIP | tee -a $out/$target.txt
f_solidLong ; f_solidLineText >> $out/$target.txt
whois -h whois.pwhois.org $target_ip > $tempdir/pwhois.txt
whois $target_ip > $tempdir/rev-whois.txt
echo -e "\n${B}AS Information ${D}\n\n"
echo -e " == $target AS INFORMATION  ==\n\n" >> $out/$target.txt
f_pwhois | tee -a $out/$target.txt
echo '' | tee -a $out/$target.txt
f_asContact | tee -a $out/$target.txt
f_solidLong ; f_solidLineText >> $out/$target.txt
timeout 3 openssl s_client -connect $target:443 -brief 2>$tempdir/ssl_sum2.txt
echo | timeout 3 openssl s_client -connect $target:443 2>>$tempdir/status.txt -status >> $tempdir/status.txt
echo | timeout 3 openssl s_client -connect $target:443 2>>$tempdir/ssl_sum2.txt | openssl x509 -text -enddate >> $tempdir/ssl_sum2.txt
cat $tempdir/ssl_sum2.txt | tr -d '"' | sed 's/AES_/AES-/g' | sed 's/ = /: /g' | sed 's/_/ - /g' | tr -d '(' | tr -d ')' |
sed 's/^ *//' > $tempdir/ssl.txt
echo -e "\n${B}Certificate Status${D}\n"
echo -e " == CERTIFICATE STATUS ==\n\n" >> $out/$target.txt
f_certSummary | tee -a $out/$target.txt
f_solidLong ; f_solidLineText >> $out/$target.txt
echo -e "\n\n${B}Description${D}\n"
echo -e "\n\n == DESCRIPTION ==\n" >> $out/$target.txt
f_targetDescription
echo -e "\n\n${B}Social Media & Contact Links ${D}\n"
echo -e "\n\n == SOCIAL MEDIA & CONTACT LINKS ==\n" >> $out/$target.txt
f_socialLinks
f_solidLineText >> $out/$target.txt
echo '' ;  f_menuDomain ; f_removeDir
;;
#********** 2) DNS RECORDS - A, AAAA, MX, NS, PTR, SOA, SRV, TXT **********
2)
f_makeNewDir ; f_dashedGrey 
echo -e "\n${B}$target Domain Host A & AAAA Records${D}\n"
echo -e " == $target DOMAIN HOST A & AAAA RECORDS ==\n\n" >> $out/$target.txt
f_aRecord | tee -a $out/$target.txt
echo -e "\n\n${B}$target_ip PTR record${D}\n"
echo -e "\n\n == PTR RECORD ==\n" >> $out/$target.txt
host -t A $target_ip | cut -d ' ' -f 3- | rev | cut -d '.' -f 2- | rev | tee -a $out/$target.txt
echo -e "\n\n${B}SOA Record${D}\n"
echo -e "\n\n == SOA RECORD ==\n" >> $out/$target.txt
dig soa +short $target | tee -a $out/$target.txt
echo -e "\n\n${B}MX Priorities${D}\n"
echo -e "\n\n == MX PRIORITIES ==\n\n" >> $out/$target.txt
mx_priorties=`dig mx +short $target` 
echo "$mx_priorties" | sort -g | uniq | tee -a $out/$target.txt
f_solidLong ; f_solidLineText  >> $out/$target.txt
echo -e "\n${B}MX A Records${D}\n"
echo -e " == MX A RECORDS ==\n\n" >> $out/$target.txt
f_mxIPv4
echo -e "\n\n == NS A RECORDS ==\n\n" >> $out/$target.txt
echo -e "${B}\nNS A Records${D}\n"
f_nsIPv4
f_solidLong ; f_solidLineText >> $out/$target.txt
echo -e "\n${B}MX AAAA Records${D}\n"
echo -e " == MX AAAA RECORDS ==\n\n" >> $out/$target.txt
f_mxIPv6
echo -e "${B}\nNS AAAA Records${D}\n"
echo -e "\n\n == NS AAAA RECORDS ==\n\n" >> $out/$target.txt
f_nsIPv6
f_solidLong ; f_solidLineText >> $out/$target.txt
echo -e "\n${B}SRV Record(s)${D}\n"
echo -e "== SRV RECORDS(S) ==\n\n" >> $out/$target.txt
host -t SRV $target | tee -a $out/$target.txt
echo -e "\n\n${B}TXT Record(s)${D}\n"
echo -e "\n\n == TXT RECORDS(S) ==\n\n" >> $out/$target.txt
txt=`host -t TXT $target`
echo "$txt"  | fmt -w 80 -s | tee -a $out/$target.txt
echo -e "\n${BDim}IPv4 Addresses found in TXT Record:${D}\n" 
echo -e "\n\n == IPv4 ADDRESSES FOUND IN TXT RECORDS(S) ==\n\n" >> $out/$target.txt
echo "$txt"  | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | tee -a $out/$target.txt
f_solidLineText >> $out/$target.txt ; f_menuDomain ; f_removeDir
;;
3)
#************** 3) server response times & tracepath (submenu domain) ********************
f_makeNewDir ; f_dashedGrey 
echo -e "\n${B}Server Status & Response Times${D}\n"
echo -e " == SERVER STATUS == \n" >> $out/$target.txt
f_connCheck
echo -e "\n${B}AAAA:${D}    $(host -t AAAA $target | cut -d ' ' -f 3- | head -1)"
echo -e "\n\n${B}Server Response Times${D}\n"
echo -e "\n == SERVER RESPONSE TIMES == \n" >> $out/$target.txt
f_resTime | tee -a $out/$target.txt
f_tracePath
f_solidLineText >> $out/$target.txt ; echo '' ; f_menuDomain ; f_removeDir
;;
4)
#************** 4) querying hackertarget.com for sites sharing common nameserver (submenu domain) ********************
f_makeNewDir ; f_dashedGrey 
echo -e "\n${B}Shared DNS Server(s) (via hackertarget.com)${D}\n"
echo -e "${B}Domain NS Records${D}\n"
echo "$ns_url"
echo -e " \n${B}Set target name server${D}\n"
echo -e -n " ${B}>>${D}  "
read targetNS
echo ''
echo -e "\n == $target Shared DNS Server(s) (via hackertarget.com) == \n" >> $out/$target.common-ns.txt
date >> $out/$target.common-ns.txt
echo '' >> $out/$target.common-ns.txt
echo -e "Nameserver: $targetNS \n" >> $out/$target.common-ns.txt
curl -s https://api.hackertarget.com/findshareddns/?q=$targetNS | tee -a $out/$target.common-ns.txt
f_solidLineText >> $out/$target.common-ns.txt ; echo '' ; f_menuDomain ; f_removeDir
;;
5)
#************** 5) subdomain enumeration (submenu domain)  ********************
f_makeNewDir
f_dashedGrey 
echo -e "\n${B}$target Subdomains (via hackertarget.com) ${D}\n\n"
echo -e "\n\n == $target SUBDOMAINS (via hackertarget.com) == \n\n" >> $out/$target.subdomains.txt
date >> $out/$target.subdomains.txt
echo '' >> $out/$target.subdomains.txt
curl -s --max-time 4 https://api.hackertarget.com/hostsearch/?q=$target | sed 's/,/ -  /g' | tee -a $out/$target.subdomains.txt
f_solidLineText >> $out/$target.subdomains.txt ; echo '' ; f_menuDomain ; f_removeDir
;;
6)
#************** 6) zone transfer check (submenu domain) ********************
f_makeNewDir ; f_dashedGrey 
echo -e "\n${B}$target Zone Transfer Check${D}\n"
echo -e " == $target ZONE TRANSFER CHECK ==\n\n" >> $out/$target.txt
f_zoneTransfer | tee -a $out/$target.txt
f_solidLineText >> $out/$target.txt ; echo '' ; f_menuDomain ; f_removeDir
;;
11)
#***********************  11) certificate information  & -file (submenu domain)  **************************
f_makeNewDir ; f_dashedGrey 
timeout 3 openssl s_client -connect $target:443 -brief 2>$tempdir/ssl_sum2.txt
echo | timeout 3 openssl s_client -connect $target:443 2>>$tempdir/status.txt -status >> $tempdir/status.txt
echo | timeout 3 openssl s_client -connect $target:443 2>>$tempdir/ssl_sum2.txt | openssl x509 -text -enddate >> $tempdir/ssl_sum2.txt
cat $tempdir/ssl_sum2.txt | tr -d '"' | sed 's/AES_/AES-/g' |  sed 's/ = /: /g' | sed 's/_/ - /g' | tr -d '(' | tr -d ')' |
sed 's/^ *//' > $tempdir/ssl.txt
echo -e "\n${B}Certificate Status & SSL/TLS Information${D}\n\n"
echo -e " == CERTIFICATE STATUS & SSL/TLS INFORMATION ==\n\n" >> $out/$target.txt
f_certInfo | tee -a $out/$target.txt
echo -e "\n\n\n${B}Certificate Chain (depth:2-1-0)${D}\n"
echo -e "\n\n\n == CERTIFICATE CHAIN (depth:2-1-0) == \n\n" >> $out/$target.txt
f_certChain | tee -a $out/$target.txt
echo -e "\n "
echo -e -n "Display Certificates & Public Key?  ${B}[y]${D} | ${B}[n]${D}  "
read answer
echo ''
if [ $answer = "y" ]; then
        f_showCerts | tee $out/$target.certificate.txt
fi
f_solidLineText >> $out/$target.txt ; echo '' ; f_Menu ; f_removeDir
;;
12)
f_optionsAS
;;
13)
f_geoOptions
;;
14)
f_optionsWhois
;;
15)
f_optionsHostSearch
;;
16)
#************** 16) reverse IP lookup (submenu IP) ********************
f_makeNewDir ; f_dashedGrey 
echo -e "\n${B}Reverse IP Lookup (via hackertarget.com)${D}\n\n"
echo -e " == REVERSE IP LOOKUP ==\n\n" >> $out/$target.txt
curl -s https://api.hackertarget.com/reverseiplookup/?q=$target | tee -a $out/$target.txt
f_solidLineText  >> $out/$target.txt ; echo '' ; f_Menu ; f_removeDir
;;
17)
f_options_Dump
;;
21)
f_makeNewDir ; f_dashedGrey 
ptr=`host -t A $target| cut -d ' ' -f 5 | rev | cut -d  '.' -f 2- | rev` 
ptr_ipv6=`host -t AAAA $ptr | cut -d ' ' -f 5`
echo -e "\n${B}PTR Record${D}\n"
echo -e " == PTR RECORD ==\n" >> $out/$target.txt
echo "$ptr"
echo -e "\n${B}AAAA Record:${D}\n"
echo "$ptr_ipv6"
f_solidLineText  >> $out/$target.txt ; echo '' ; f_menuIP ; f_removeDir
;;
22)
#******************* 22) website overview (submenu IP)  **********************
f_makeNewDir ; f_dashedGrey 
f_connCheck
echo -e "\n" | tee -a $out/$target.txt
f_headers
echo -e "\n\n${B}PTR Record${D}\n"
echo -e "\n\n == PTR RECORD ==\n" >> $out/$target.txt
host -t A $target | cut -d ' ' -f 3- | rev | cut -d '.' -f 2- | rev | tee -a $out/$target.txt
echo -e "\n\n${B}Website Title${D}\n"
echo -e "\n\n == WEBSITE TITLE ==\n" >> $out/$target.txt
f_website_Title | tee -a $out/$target.txt
f_solidLong ; f_solidLineText  >> $out/$target.txt
echo -e "\n${B}$target_ip IP Geolocation (via ip-api.co)${D}\n"
echo -e " == $target_ip IP GEOLOCATION (via ip-api.co) ==\n"  >> $out/$target.txt
f_geoIP | tee -a $out/$target.txt
f_solidLong ; f_solidLineText  >> $out/$target.txt
whois -h whois.pwhois.org $target_ip > $tempdir/pwhois.txt
whois $target_ip > $tempdir/rev-whois.txt
echo -e "\n${B}AS Information ${D}\n\n"
echo -e " == $target AS INFORMATION  ==\n\n" >> $out/$target.txt
f_pwhois | tee -a $out/$target.txt
echo '' | tee -a $out/$target.txt
f_asContact | tee -a $out/$target.txt
f_solidLong ; f_solidLineText >> $out/$target.txt
timeout 3 openssl s_client -connect $target:443 -brief 2>$tempdir/ssl_sum2.txt
echo | timeout 3 openssl s_client -connect $target:443 2>>$tempdir/status.txt -status >> $tempdir/status.txt
echo | timeout 3 openssl s_client -connect $target:443 2>>$tempdir/ssl_sum2.txt | openssl x509 -text -enddate >> $tempdir/ssl_sum2.txt
cat $tempdir/ssl_sum2.txt | tr -d '"' | sed 's/AES_/AES-/g' | sed 's/ = /: /g' | sed 's/_/ - /g' | tr -d '(' | tr -d ')' |
sed 's/^ *//' > $tempdir/ssl.txt
echo -e "\n${B}Certificate Status & SSL/TLS Information${D}\n\n"
echo -e " == CERTIFICATE STATUS & SSL/TLS INFORMATION ==\n\n" >> $out/$target.txt
f_certSummary | tee -a $out/$target.txt
f_solidLineText  >> $out/$target.txt ; echo '' ; f_menuIP ; f_removeDir
;;
23)
#************** 23) server response times & tracepath (submenu IP) ********************
f_makeNewDir ; f_dashedGrey 
target=`echo $target_ip`
echo -e "\n${B}Server Status & Response Times${D}\n"
echo -e " == SERVER STATUS == \n" >> $out/$target.txt
f_connCheck
echo -e "\n\n${B}Server Response Times${D}\n"
echo -e "\n\n == SERVER RESPONSE TIMES == \n" >> $out/$target.txt
f_resTime | tee -a $out/$target.txt
f_tracePath
f_solidLineText  >> $out/$target.txt ; echo '' ; f_menuIP ; f_removeDir
;;
31)
f_makeNewDir ; f_dashedGrey 
echo -e "\n${B}$target_ip Geolocation ${D}\n\n"
echo -e "\n == $target_ip IP GEOLOCATION (via ipapi.co) ==\n\n"  >> $out/$target.txt
address=`echo $target_ip`
f_geoIP | tee -a $out/$target.txt
f_solidLineText  >> $out/$target.txt ; echo '' ; f_Menu ; f_removeDir 
;;
32)
#************** CUSTOM DOMAIN/IP GEOLOCATION ********************
f_makeNewDir ; f_dashedGrey 
echo -e "\n${B}IP Geolocation - Custom Input${D}\n"
echo -e " Set Target  ${B}Domain${D} or ${B}IP${D}\n"
echo -e -n "  ${B}>>${D}  "
read geo_target
echo -e "\n "
 if [[ $geo_target =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
       address=`echo $geo_target`
        echo -e "\n == $geo_target IP GEOLOCATION ==\n\n"  >> $out/$target.txt
        f_geoIP | tee -a $out/$target.txt; else
        address=`host -t A $geo_target | head -1 | cut -d " " -f 4`
        echo -e "\n${B}$address Geolocation${D}\n\n"
        echo -e " == $geo_target IP GEOLOCATION (via ipapi.co) ==\n\n"  >> $out/$target.txt
        f_geoIP | tee -a $out/$target.txt
fi
f_solidLineText  >> $out/$target.txt ; echo '' ; f_Menu ; f_removeDir
;;
41)
#************** 41) TARGET WHOIS ********************
f_makeNewDir ; f_dashedGrey 
echo -e "\n${B}$target whois Lookup${D}\n"
if [[ $target =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then 
    whois $target  > $tempdir/rev-whois.txt
    echo -e "\n${B}$target reverse whois${D}\n\n"
    echo -e " == $target REVERSE WHOIS  ==\n\n" >> $out/$target.txt
    f_drwho
else
    echo -e " == $target WHOIS SUMMARY ==\n" >> $out/$target.txt
    whois $target > $tempdir/host-whois.txt   
    f_whoisRequest
    whois $target_ip  > $tempdir/rev-whois.txt
    echo -e "\n${B}$target reverse whois${D}\n\n"
    echo -e "\n\n == $target ($target_ip) REVERSE WHOIS ==\n\n" >> $out/$target.txt
    f_drwho
fi
f_solidLineText  >> $out/$target.txt ; echo '' ; f_Menu ; f_optionsWhois ; f_removeDir
;;
42)
#**************  42) CUSTOM DOMAIN/IP WHOIS ********************
f_makeNewDir ; f_dashedGrey 
echo -e "\n${B}whois - Custom Input${D}\n"
echo -e "  Set target ${B}DOMAIN${D} or ${B}IP${D}\n"
echo -e -n "  ${B}>>${D}  "
read whois_target
if [[ $whois_target =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    whois_ip=`echo $whois_target`; 
    whois $whois_ip  > $tempdir/rev-whois.txt
    echo -e "\n${B}$whois_target reverse whois ${D}\n\n"
    echo -e " == $whois_target REVERSE WHOIS ==\n\n" >> $out/$target.txt
    f_drwho
    else
    whois_ip=`host -t A $whois_target | head -1 | cut -d " " -f 4`
    echo -e "\n\n${B}$whois_target whois Summmary${D}\n"
    echo -e " == $whois_target WHOIS SUMMARY ==\n" >> $out/$target.txt
    whois $whois_target > $tempdir/host-whois.txt   
    f_whoisRequest
    whois $whois_ip  > $tempdir/rev-whois.txt
    echo -e "\n\n${B}$whois_target reverse whois${D}\n\n"
    echo -e "\n\n== $whois_target REVERSE WHOIS ==\n\n" >> $out/$target.txt
    f_drwho
fi
f_solidLineText  >> $out/$target.txt ; echo '' ; f_Menu ; f_optionsWhois ; f_removeDir
;;
51)
#************** 51) target IPv4 ADDRESS BLOCK HOST SEARCH  ********************
f_makeNewDir ; f_dashedGrey 
prefx=`dig x +short $target | rev | cut -d '.' -f 2- | rev`
echo -e "\n${B}target Address Block Reverse Host Search ${D}\n\n"
echo -e " == $target_ip ADDRESS BLOCK REVERSE HOST SEARCH == \n" >> $out/$target.subdomains.txt
echo -e "$(date) \n" >> $out/$target.subdomains.txt
f_hostSearch | tee -a $out/$target.subdomains.txt
f_solidLineText >> $out/$target.subdomains.txt 
echo '' ; f_Menu ; f_optionsHostSearch ; f_removeDir
;;
52)
#************** 52) CUSTOM IPv4 ADDRESS BLOCK HOST SEARCH  ********************
f_makeNewDir ; f_dashedGrey ; f_getPrefixes
echo -e "\n${B}Reverse Host Search - Custom Input${D}\n"
echo -e "${B}Host prefix:${D}  $target_prefix "
echo -e "\nFor further enumeration you may want to pick one of the following IPv4-prefixes:\n"
echo -e "${BDim}IPv4 Prefixes (NS- Records):${D}"            
cat $tempdir/ns_prefixes.txt | sort | uniq        
echo -e "${BDim}IPv4 Prefixes (MX- Records):${D}"
cat $tempdir/mx_prefixes.txt | sort | uniq
echo -e "${BDim}IPv4 Prefixes (TXT Record:)${D}"
cat $tempdir/txt_prefixes.txt | sort | uniq
echo ''
echo -e -n "Proceed? ${B}[y]${D} yes | ${B}[n]${D}  " ; read answer
if [ $answer = "y" ]; then
    echo -e "\n\nPlease enter a network prefix:\n "
    echo -e -n "  ${B}>>${D}  " ; read prefx
    echo '' ; f_solidLineText >> $out/$target.subdomains.txt 
    echo -e "== $prefx ADDRESS BLOCK REVERSE HOST SEARCH ==\n" >> $out/$target.subdomains.txt
    echo -e "$(date) \n" >> $out/$target.subdomains.txt
    f_hostSearch | tee -a $out/$target.subdomains.txt
fi
f_solidLineText  >> $out/$target.subdomains.txt
echo '' ; f_Menu ; f_optionsHostSearch ; f_removeDir
;;
71)
#************** 71) HTTP headers  ********************
f_makeNewDir ; f_dashedGrey 
echo -e "\n${B}HTTP Headers${D}\n"
echo -e " == HTTP HEADERS ==\n\n" >> $out/$target.txt
curl -s -I -L --max-time 4 $target | tee -a $out/$target.txt
f_solidLineText  >> $out/$target.txt ; echo '' ; f_Menu ; f_options_Dump ; f_removeDir
;;
72)
#************** robots.txt  ********************
f_makeNewDir ; f_dashedGrey 
echo -e "\n${B}robots.txt${D}\n"
echo -e " == robots.txt ==\n\n" >> $out/$target.txt
curl -s -L --max-time 4 $target/robots.txt | tee -a $out/$target.txt
f_solidLineText  >> $out/$target.txt ; echo '' ; f_Menu ; f_options_Dump ; f_removeDir
;;
73)
#************** link dump   ********************
f_makeNewDir ; f_dashedGrey 
echo -e "\n${B}Link Dump${D}\n"
echo -e "== LINK DUMP ==\n" >> $out/$target.txt
f_linkDump
f_solidLineText  >> $out/$target.txt ; echo '' ; f_Menu ; f_options_Dump ; f_removeDir
;;
pp)
#************** 111) nmap ping sweep ********************
f_dashedGrey
echo -e "\n\n${B}nmap ping sweep${D}\n"
echo -e " Set target ${B}Network${D}\n"
echo -e -n " ${B}>>${D}  "
read network_id
echo ''
nmap -sn $network_id | sed 's/Nmap scan/\nNmap scan/' | sed '/Nmap done/d'
echo '' ; f_optionsNMAP ; f_dashedGrey ; f_startMenu
;;
pt)
#************** 112) nmap port scan (via hackertarget.com) ********************
f_dashedGrey 
echo -e "\n${B}nmap Port Scan (via hackertarget.com)${D}\n\n"
echo -e "  Set target ${B}domain${D} or ${B}IP${D}\n"
echo -e -n "  ${B}>>${D}  " ; read scan_target
echo ''
curl -s http://api.hackertarget.com/nmap/?q=$scan_target 
echo '' ; f_optionsNMAP ; f_dashedGrey ; f_startMenu
;;
122)
# ************* AS info ******************
f_makeNewDir ; f_dashedGrey 
whois -h whois.pwhois.org $target_ip > $tempdir/pwhois.txt
whois $target_ip > $tempdir/rev-whois.txt
echo -e "\n${B}AS Information ${D}\n\n"
echo -e " == $target AS INFORMATION  ==\n\n" >> $out/$target.txt
f_pwhois | tee -a $out/$target.txt
echo '' | tee -a $out/$target.txt
f_asContact | tee -a $out/$target.txt
f_solidLineText >> $out/$target.txt ; f_Menu ; f_optionsAS ; f_removeDir
;;
123)
# ************* AS info ******************
f_makeNewDir ; f_dashedGrey 
echo -e "\n${B}AS Information ${D}\n\n"
echo -e " Set Target ${B}IP${D}\n"
echo -e -n "  ${B}>>${D}  " ; read as_target
echo -e "\n "
 if [[ $as_target =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        whois -h whois.pwhois.org $as_target > $tempdir/pwhois.txt
        whois $as_target > $tempdir/rev-whois.txt
        echo -e "\n == $as_target AS INFORMATION ==\n\n"  >> $out/$target.txt
        f_pwhois | tee -a $out/$target.txt
        echo '' | tee -a $out/$target.txt
        f_asContact | tee -a $out/$target.txt
        echo '' | tee -a $out/$target.txt
        f_solidLineText >> $out/$target.txt
        else
        echo -e "\n${R}Please enter a valid IPv4 address${D}\n"
 fi
f_Menu ; f_optionsAS ; f_removeDir
;;
q)
echo -e "\n${B}------------------------------- Done ---------------------------------\n"
echo -e "                  ${BDim}Author - Thomas Wy, Sept 2020${D}\n\n"
f_removeDir
break
;;
esac
done

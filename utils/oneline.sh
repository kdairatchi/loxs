#!/bin/bash

TARGET="$1"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

echo "[*] Running WHOIS..."
whois "$TARGET" > whois.txt 2>/dev/null

echo "[*] Running subdomain enumeration..."
subfinder -d "$TARGET" -o subs_subfinder.txt 2>/dev/null
curl -s https://crt.sh/\?q\=%.$TARGET.com\&output\=json | jq -r '.[].name_value' | sed 's/\*//g' | sort -u > subs_crtsh.txt
curl -s "https://dns.bufferover.run/dns?q=%.$TARGET" | jq -r '.FDNS_A[]?' 2>/dev/null | cut -d',' -f2 | sort -u > subs_bufferover.txt
curl -s "http://web.archive.org/cdx/search/cdx?url=*.$TARGET/*&output=text&fl=original&collapse=urlkey" 2>/dev/null | sed -e 's|https*://||' -e 's|/.*||' | sort -u > subs_webarchive.txt
curl -s "https://sonar.omnisint.io/subdomains/$TARGET" 2>/dev/null | grep -oE "[A-Za-z0-9._-]+\.$TARGET" | sort -u > subs_omnisint.txt
assetfinder --subs-only "$TARGET" | sort -u > subs_assetfinder.txt 2>/dev/null
amass enum -passive -d "$TARGET" > subs_amass.txt 2>/dev/null

cat subs_*.txt | sort -u > subs.txt

echo "[*] Running DNS queries..."
for type in A AAAA CNAME MX NS TXT SOA; do
    dig +short $type "$TARGET" >> dns_$type.txt
done

echo "[*] Collecting IPs..."
awk '{print $1}' dns_A.txt >> ip.txt 2>/dev/null
awk '{print $1}' dns_AAAA.txt >> ip.txt 2>/dev/null
sqry -q ssl:"$TARGET" >> ip.txt 2>/dev/null
sqry -q hostname:"$TARGET" >> ip.txt 2>/dev/null
sqry -q "$TARGET" >> ip.txt 2>/dev/null

sort -u ip.txt -o ip.txt

if [ -s ip.txt ]; then
    echo "[*] Running hunter_enhanced..."
    python3 hunter.py ip.txt --cve+ports --html-output hunter_report.html --screenshot
fi

echo "[*] Probing live hosts..."
cat ips.txt | httpx -status-code -title -o liveips.txt 2>/dev/null
cat subs.txt | httpx -status-code -title -silent -sr -o live.txt 2>/dev/null

echo "[*] Running nuclei..."
awk '{print $1}' live.txt | nuclei -silent -o nuclei.txt 2>/dev/null

echo "[*] Collecting URLs..."
echo "$TARGET" | gau >> urls.txt 2>/dev/null
echo "$TARGET" | waybackurls >> urls.txt 2>/dev/null
echo "https://$TARGET" | hakrawler >> urls.txt 2>/dev/null
echo "https://$TARGET" | katana >> urls.txt 2>/dev/null
echo "$TARGET" | urlfinder >> urls.txt 2>/dev/null
curl -s "http://web.archive.org/cdx/search/cdx?url=*.$TARGET/*&output=text&fl=original&collapse=urlkey" >> urls.txt
sort -u urls.txt -o urls.txt

echo "[*] Running GF patterns..."
for pat in xss ssti sqli lfi rce redirect ssrf idor open-redirect; do
    gf "$pat" < urls.txt | sort -u > gf_$pat.txt
    sed 's/=[^&]*//g' gf_$pat.txt | sed 's/[?&]$//' | sort -u > gf_${pat}_params.txt
done

echo "[*] Screenshotting hosts..."
gowitness file -f live.txt -P screenshots/ 2>/dev/null
cat subs.txt | aquatone -out aquatone/ 2>/dev/null

echo "[*] Running nmap..."
nmap -T4 -F -iL live.txt -oN nmap.txt 2>/dev/null

echo "[*] Checking for SQLi..."
sqlmap -m gf_sqli.txt --batch --random-agent -o 2>/dev/null

echo "[*] Running nuclei CVE templates..."
nuclei -l live.txt -t cves/ -o nuclei_cves.txt 2>/dev/null

echo "[*] Done ✅"

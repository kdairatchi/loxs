#!/usr/bin/env bash
# Ultra OSINT Domain Recon Tool
# Author: kdairatchi edition ++ (parallel, resilient)
# Purpose: Enumerate subs, collect DNS, probe HTTP, fuzz with gf/nuclei, OSINT APIs

###############################################################################
# Config & setup
###############################################################################
TARGET="$1"
if [ -z "$TARGET" ]; then
  echo "Usage: $0 <domain>"
  exit 1
fi

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_DIR="osint_results/${TARGET}_${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR" "$OUTPUT_DIR"/{dns,gf,logs,screenshots}

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
RESET='\033[0m'

LOG_FILE="$OUTPUT_DIR/logs/run.log"
MAX_JOBS=${MAX_JOBS:-8}
ULIMIT_FD=$(ulimit -n 2>/dev/null || echo 256)

###############################################################################
# Pretty printing
###############################################################################
banner() {
  echo -e "${CYAN}========================================"
  echo -e "            OSINT SCANNER                      "
  echo -e "========================================${RESET}"
}
log()      { echo -e "[${YELLOW}→${RESET}] $1"; echo "[*] $1" >>"$LOG_FILE"; }
success()  { echo -e "[${GREEN}✓${RESET}] $1"; echo "[+] $1" >>"$LOG_FILE"; }
section()  { echo -e "${CYAN}[===] $1${RESET}"; echo "[===] $1" >>"$LOG_FILE"; }
warn()     { echo -e "[${YELLOW}!${RESET}] $1"; echo "[!] $1" >>"$LOG_FILE"; }
error()    { echo -e "[${RED}x${RESET}] $1"; echo "[-] $1" >>"$LOG_FILE"; }

banner
echo "[===] Starting OSINT Scan for: ${TARGET}"

###############################################################################
# Simple semaphore for parallelization
###############################################################################
sem_init() {  # create $MAX_JOBS tokens on FD 3
  mkfifo "/tmp/sem.$$" || exit 1
  exec 3<> "/tmp/sem.$$"
  rm -f "/tmp/sem.$$"
  for _ in $(seq 1 "$MAX_JOBS"); do
    printf '.' >&3
  done
}
sem_wait() { read -u 3 -r _; }
sem_post() { printf '.' >&3; }
sem_close(){ exec 3>&-; }

sem_init

###############################################################################
# WHOIS
###############################################################################
section "WHOIS Lookup"
log "Starting: whois_lookup"
if command -v whois >/dev/null 2>&1; then
  whois "$TARGET" > "$OUTPUT_DIR/whois.txt" 2>>"$LOG_FILE" || true
  success "WHOIS saved to $OUTPUT_DIR/whois.txt"
else
  warn "whois not installed"
fi

###############################################################################
# Subdomain Enumeration (parallel)
###############################################################################
section "Subdomain Enumeration"
SUBDOMAIN_FILE="$OUTPUT_DIR/subdomains.txt"
TMP_SUBS_DIR="$OUTPUT_DIR/.subs"
mkdir -p "$TMP_SUBS_DIR"

run_src() {
  local name="$1"
  local cmd="$2"
  sem_wait
  {
    log "Running ${name}..."
    bash -c "$cmd" 2>>"$LOG_FILE" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' \
      | grep -E "\.${TARGET}$" || true
    sem_post
  } >>"$TMP_SUBS_DIR/${name}.txt" &
}

# API sources
run_src "crtsh"       "curl -s 'https://crt.sh/?q=%25.${TARGET}&output=json' | jq -r '.[].name_value' | sed 's/\*\.//g' | tr ' ' '\n' | sort -u"
run_src "bufferover"  "curl -s 'https://dns.bufferover.run/dns?q=.${TARGET}' | jq -r '.FDNS_A[]?' | cut -d',' -f2 | sort -u"
run_src "webarchive"  "curl -s 'http://web.archive.org/cdx/search/cdx?url=*.${TARGET}/*&output=text&fl=original&collapse=urlkey' | sed -e 's|https*://||' -e 's|/.*||' | sort -u"
run_src "omnisint"    "curl -s 'https://sonar.omnisint.io/subdomains/${TARGET}' | grep -oE '[A-Za-z0-9._-]+\.${TARGET}' | sort -u"

# Local tools (only if present)
if command -v assetfinder >/dev/null 2>&1; then
  run_src "assetfinder" "assetfinder --subs-only ${TARGET} | sort -u"
fi
if command -v subfinder >/dev/null 2>&1; then
  run_src "subfinder" "subfinder -silent -d ${TARGET}"
fi
if command -v amass >/dev/null 2>&1; then
  run_src "amass" "amass enum -passive -d ${TARGET}"
fi

wait
cat "$TMP_SUBS_DIR"/*.txt 2>/dev/null | sort -u > "$SUBDOMAIN_FILE"
rm -rf "$TMP_SUBS_DIR"
success "Subdomains saved to $SUBDOMAIN_FILE ($(wc -l < "$SUBDOMAIN_FILE" 2>/dev/null || echo 0))"

###############################################################################
# DNS Resolution (parallel)
###############################################################################
section "DNS Resolution"
DNS_DIR="$OUTPUT_DIR/dns"
mkdir -p "$DNS_DIR"
> "$DNS_DIR/A.txt"; > "$DNS_DIR/AAAA.txt"; > "$DNS_DIR/CNAME.txt"
> "$DNS_DIR/MX.txt"; > "$DNS_DIR/NS.txt";  > "$DNS_DIR/TXT.txt"; > "$DNS_DIR/SOA.txt"

resolve_one() {
  local host="$1" type="$2"
  sem_wait
  {
    dig +short "$type" "$host" 2>>"$LOG_FILE" | awk -v h="$host" -v t="$type" '{print h"\t"t"\t"$0}' || true
    sem_post
  } >> "$DNS_DIR/${type}.txt" &
}

if [ -s "$SUBDOMAIN_FILE" ]; then
  while IFS= read -r sub; do
    for t in A AAAA CNAME MX NS TXT SOA; do
      resolve_one "$sub" "$t"
    done
  done < "$SUBDOMAIN_FILE"
  wait
  for f in "$DNS_DIR"/*.txt; do sort -u "$f" -o "$f"; done
  success "DNS records saved under $DNS_DIR/"
else
  warn "No subdomains to resolve"
fi

###############################################################################
# IP Collection (sqry + DNS A/AAAA)
###############################################################################
IP_FILE="$OUTPUT_DIR/ip.txt"
> "$IP_FILE"

# from DNS A/AAAA
awk '{print $3}' "$DNS_DIR/A.txt"    2>/dev/null | grep -E '^[0-9.]+$'   >> "$IP_FILE" || true
awk '{print $3}' "$DNS_DIR/AAAA.txt" 2>/dev/null | grep -E '[:0-9a-f]+' >> "$IP_FILE" || true

# from sqry (if present)
if command -v sqry >/dev/null 2>&1; then
  section "IP Collection (sqry)"
  sem_wait; { sqry -q "ssl:${TARGET}"      2>>"$LOG_FILE" || true; sem_post; } >> "$IP_FILE" &
  sem_wait; { sqry -q "hostname:${TARGET}" 2>>"$LOG_FILE" || true; sem_post; } >> "$IP_FILE" &
  wait
fi

sort -u "$IP_FILE" -o "$IP_FILE"
success "IP list saved to $IP_FILE ($(wc -l < "$IP_FILE" 2>/dev/null || echo 0))"

# ------------------ Enhanced IP Recon (hunter_enhanced.py) ------------------
log "Starting: ip_recon"
section "Enhanced IP Recon"

if [ -s "$OUTPUT_DIR/ip.txt" ] && command -v python3 &>/dev/null; then
    HUNTER_OUT="$OUTPUT_DIR/hunter_report.html"
    log "Running hunter_enhanced.py on collected IPs..."
    
    python3 hunter_enhanced.py "$OUTPUT_DIR/ip.txt" \
        --cve+ports \
        --html-output "$HUNTER_OUT" \
        --threads 20 --timeout 20 --quiet || true
    
    if [ -f "$HUNTER_OUT" ]; then
        success "Hunter report saved to $HUNTER_OUT"
    else
        echo -e "${RED}[x] Hunter scan failed or no results${RESET}"
    fi
else
    echo -e "${RED}[x] Skipping hunter_enhanced.py (no IPs or python3 missing)${RESET}"
fi

###############################################################################
# URL Discovery (parallel) + dedupe
###############################################################################
section "URL Discovery"
URL_FILE="$OUTPUT_DIR/urls.txt"
> "$URL_FILE"
TMP_URL_DIR="$OUTPUT_DIR/.urls"
mkdir -p "$TMP_URL_DIR"

url_src() {
  local name="$1" cmd="$2"
  sem_wait
  {
    bash -c "$cmd" 2>>"$LOG_FILE" || true
    sem_post
  } >> "$TMP_URL_DIR/${name}.txt" &
}

if command -v gau >/dev/null 2>&1; then
  url_src "gau" "echo ${TARGET} | gau"
fi
if command -v waybackurls >/dev/null 2>&1; then
  url_src "waybackurls" "echo ${TARGET} | waybackurls"
fi
if command -v hakrawler >/dev/null 2>&1; then
  url_src "hakrawler" "echo https://${TARGET} | hakrawler"
fi
if command -v katana >/dev/null 2>&1; then
  url_src "katana" "echo https://${TARGET} | katana -silent"
fi

# Fallback to webarchive if no tools
url_src "webarchive" "curl -s 'http://web.archive.org/cdx/search/cdx?url=*.${TARGET}/*&output=text&fl=original&collapse=urlkey'"

wait
cat "$TMP_URL_DIR"/*.txt 2>/dev/null | sed 's/#.*$//' | sort -u > "$URL_FILE"
rm -rf "$TMP_URL_DIR"
success "URLs saved to $URL_FILE ($(wc -l < "$URL_FILE" 2>/dev/null || echo 0))"

###############################################################################
# GF Patterns (all patterns) + param-stripped companion files
###############################################################################
if command -v gf >/dev/null 2>&1 && [ -s "$URL_FILE" ]; then
  section "GF Pattern Matching"
  PAT_DIR="$OUTPUT_DIR/gf"
  mkdir -p "$PAT_DIR"

  # If gf -list fails, fall back to a useful default set
  mapfile -t PATTERNS < <(gf -list 2>/dev/null || echo -e "xss\nssti\nsqli\nlfi\nrce\nredirect\nssrf\nidor\nopen-redirect")
  for pat in "${PATTERNS[@]}"; do
    sem_wait
    {
      log "gf: ${pat}"
      # Full matches
      gf "$pat" < "$URL_FILE" 2>>"$LOG_FILE" | sort -u > "$PAT_DIR/${pat}.txt" || true
      # Param-stripped (up to '='; useful for quick testing wordlists)
      sed 's/=[^&]*//g' "$PAT_DIR/${pat}.txt" | sed 's/[?&]$//' | sort -u > "$PAT_DIR/${pat}_params.txt"
      sem_post
    } &
  done
  wait
  success "GF outputs saved in $PAT_DIR/ (including *_params.txt)"
else
  warn "gf not installed or URL list empty; skipping GF"
fi

###############################################################################
# Port Scanning (nmap)
###############################################################################
section "Port Scanning"
if command -v nmap >/dev/null 2>&1; then
  nmap -Pn -T4 --top-ports 100 "$TARGET" -oN "$OUTPUT_DIR/nmap.txt" 2>>"$LOG_FILE" || true
  success "Nmap scan saved to $OUTPUT_DIR/nmap.txt"
else
  warn "nmap not installed"
fi

###############################################################################
# HTTP Probing (httpx)
###############################################################################
section "HTTP Probing"
HTTPX_OUT="$OUTPUT_DIR/httpx.txt"
if command -v httpx >/dev/null 2>&1 && [ -s "$SUBDOMAIN_FILE" ]; then
  # Output includes status/title; -sr saves responses in ./httpx/ by default
  cat "$SUBDOMAIN_FILE" | httpx -status-code -title -silent -sr -o "$HTTPX_OUT" 2>>"$LOG_FILE" || true
  success "HTTP probe saved to $HTTPX_OUT"
else
  warn "httpx not installed or no subdomains"
fi

###############################################################################
# Vulnerability Scanning (nuclei)
###############################################################################
section "Vulnerability Scan (nuclei)"
if command -v nuclei >/dev/null 2>&1 && [ -s "$HTTPX_OUT" ]; then
  # Extract URL column (first whitespace-delimited field)
  awk '{print $1}' "$HTTPX_OUT" | nuclei -silent -o "$OUTPUT_DIR/nuclei.txt" 2>>"$LOG_FILE" || true
  success "Nuclei scan saved to $OUTPUT_DIR/nuclei.txt"
else
  warn "nuclei not installed or no httpx results"
fi

###############################################################################
# Screenshots (gowitness/aquatone)
###############################################################################
section "Web Screenshots"
if command -v gowitness >/dev/null 2>&1 && [ -s "$SUBDOMAIN_FILE" ]; then
  gowitness file -f "$SUBDOMAIN_FILE" -P "$OUTPUT_DIR/screenshots" 2>>"$LOG_FILE" || true
  success "Screenshots saved to $OUTPUT_DIR/screenshots/"
elif command -v aquatone >/dev/null 2>&1 && [ -s "$SUBDOMAIN_FILE" ]; then
  cat "$SUBDOMAIN_FILE" | aquatone -out "$OUTPUT_DIR/aquatone" 2>>"$LOG_FILE" || true
  success "Screenshots saved to $OUTPUT_DIR/aquatone/"
else
  warn "gowitness/aquatone not installed or no subdomains"
fi

###############################################################################
# Simple HTML Report
###############################################################################
section "Report"
REPORT="$OUTPUT_DIR/report.html"
SUB_COUNT=$(wc -l < "$SUBDOMAIN_FILE" 2>/dev/null || echo 0)
IP_COUNT=$(wc -l < "$IP_FILE" 2>/dev/null || echo 0)
URL_COUNT=$(wc -l < "$URL_FILE" 2>/dev/null || echo 0)
HTTPX_COUNT=$(wc -l < "$HTTPX_OUT" 2>/dev/null || echo 0)
NUCLEI_COUNT=$(wc -l < "$OUTPUT_DIR/nuclei.txt" 2>/dev/null || echo 0)

cat > "$REPORT" <<EOF
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OSINT Report - $TARGET</title>
<style>
body{font-family:Arial, sans-serif; margin:40px; background:#f4f4f4;}
.container{background:#fff; padding:30px; border-radius:10px; box-shadow:0 0 10px rgba(0,0,0,0.1);}
h1{color:#333; border-bottom:2px solid #007acc; padding-bottom:10px;}
.stats{display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:16px; margin:20px 0;}
.card{background:#007acc; color:#fff; padding:16px; border-radius:8px; text-align:center;}
.num{font-size:2em; font-weight:bold;}
pre{background:#f8f8f8; padding:12px; border-radius:6px; overflow-x:auto;}
</style>
</head><body><div class="container">
<h1>OSINT Report for $TARGET</h1>
<p>Generated: $(date)</p>
<div class="stats">
  <div class="card"><div class="num">$SUB_COUNT</div><div>Subdomains</div></div>
  <div class="card"><div class="num">$IP_COUNT</div><div>IP Addresses</div></div>
  <div class="section">
      <h2>Hunter Enhanced IP Recon Report</h2>
      <p><a href="hunter_report.html" target="_blank">Open Hunter Report</a></p>
  </div>
  <div class="card"><div class="num">$URL_COUNT</div><div>URLs</div></div>
  <div class="card"><div class="num">$HTTPX_COUNT</div><div>HTTP Probed</div></div>
  <div class="card"><div class="num">$NUCLEI_COUNT</div><div>Nuclei Findings (lines)</div></div>
</div>

<h2>Top Subdomains</h2>
<pre>$(head -20 "$SUBDOMAIN_FILE" 2>/dev/null || echo "No subdomains")</pre>

<h2>Sample Nuclei Findings</h2>
<pre>$(head -20 "$OUTPUT_DIR/nuclei.txt" 2>/dev/null || echo "No nuclei results")</pre>

<h2>Sample HTTPX</h2>
<pre>$(head -20 "$HTTPX_OUT" 2>/dev/null || echo "No httpx results")</pre>
</div></body></html>
EOF

success "Report generated: $REPORT"
sem_close
echo -e "${GREEN}OSINT Scan Complete! Results in $OUTPUT_DIR${RESET}"

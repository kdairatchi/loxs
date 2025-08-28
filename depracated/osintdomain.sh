#!/bin/bash
# Ultra OSINT Domain Recon Tool
# Author: kdairatchi edition ++
# Purpose: Enumerate subs, collect DNS, probe HTTP, fuzz with gf/nuclei, OSINT APIs

TARGET="$1"
if [ -z "$TARGET" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_DIR="osint_results/${TARGET}_${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RESET='\033[0m'

banner() {
    echo -e "${CYAN}========================================"
    echo -e "          ULTRA OSINT SCANNER           "
    echo -e "========================================${RESET}"
}

log() { echo -e "[${YELLOW}→${RESET}] $1"; }
success() { echo -e "[${GREEN}✓${RESET}] $1"; }
section() { echo -e "${CYAN}[===] $1${RESET}"; }

banner
echo "[===] Starting OSINT Scan for: ${TARGET}"

# ------------------ WHOIS ------------------
log "Starting: whois_lookup"
section "WHOIS Lookup"
whois "$TARGET" > "$OUTPUT_DIR/whois.txt" 2>/dev/null || true
success "WHOIS saved to $OUTPUT_DIR/whois.txt"

# ------------------ Subdomain Enumeration ------------------
log "Starting: subdomain_enum"
section "Subdomain Enumeration"
SUBDOMAIN_FILE="$OUTPUT_DIR/subdomains.txt"
touch "$SUBDOMAIN_FILE"

# API-based sources
log "Running crt.sh..."
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | \
    jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sort -u >> "$SUBDOMAIN_FILE"

log "Running bufferover..."
curl -s "https://dns.bufferover.run/dns?q=.$TARGET" | \
    jq -r '.FDNS_A[]?' 2>/dev/null | cut -d',' -f2 | sort -u >> "$SUBDOMAIN_FILE"

log "Running webarchive..."
curl -s "http://web.archive.org/cdx/search/cdx?url=*.$TARGET/*&output=text&fl=original&collapse=urlkey" | \
    sed -e 's|https*://||' -e 's|/.*||' | sort -u >> "$SUBDOMAIN_FILE"

log "Running omnisint..."
curl -s "https://sonar.omnisint.io/subdomains/$TARGET" | \
    grep -oE "[a-zA-Z0-9._-]+\\.$TARGET" | sort -u >> "$SUBDOMAIN_FILE"

# Installed tools
if command -v assetfinder &>/dev/null; then
    log "Running assetfinder..."
    assetfinder --subs-only "$TARGET" >> "$SUBDOMAIN_FILE"
fi

if command -v subfinder &>/dev/null; then
    log "Running subfinder..."
    subfinder -silent -d "$TARGET" >> "$SUBDOMAIN_FILE"
fi

if command -v amass &>/dev/null; then
    log "Running amass..."
    amass enum -passive -d "$TARGET" >> "$SUBDOMAIN_FILE"
fi

sort -u "$SUBDOMAIN_FILE" -o "$SUBDOMAIN_FILE"
success "Subdomains saved to $SUBDOMAIN_FILE"

# ------------------ DNS Resolution ------------------
log "Starting: dns_resolution"
section "DNS Resolution"
DNS_FILE="$OUTPUT_DIR/dns.txt"
dns_types=(A AAAA CNAME MX NS TXT SOA)

for sub in $(cat "$SUBDOMAIN_FILE"); do
    for dtype in "${dns_types[@]}"; do
        dig +short "$sub" "$dtype" >> "$DNS_FILE" 2>/dev/null || true
    done
done
success "DNS records saved to $DNS_FILE"

# ------------------ IP Collection (sqry) ------------------
if command -v sqry &>/dev/null; then
    log "Starting: ip_collection (sqry)"
    sqry -q "ssl:$TARGET" >> "$OUTPUT_DIR/ip.txt" 2>/dev/null || true &
    sqry -q "hostname:$TARGET" >> "$OUTPUT_DIR/ip.txt" 2>/dev/null || true &
    wait
    sort -u "$OUTPUT_DIR/ip.txt" -o "$OUTPUT_DIR/ip.txt"
    success "IPs saved to $OUTPUT_DIR/ip.txt"
fi

# ------------------ URL Discovery ------------------
log "Starting: url_discovery"
section "URL Discovery"
URL_FILE="$OUTPUT_DIR/urls.txt"

if command -v gau &>/dev/null; then
    echo "$TARGET" | gau >> "$URL_FILE"
fi
if command -v waybackurls &>/dev/null; then
    waybackurls "$TARGET" >> "$URL_FILE"
fi
fi
if command -v urlfider &>/dev/null; then
    urlfinder "$TARGET" >> "$URL_FILE"
fi
if command -v hakrawler &>/dev/null; then
    echo "$TARGET" | hakrawler >> "$URL_FILE"
fi

# Unique + clean
sort -u "$URL_FILE" -o "$URL_FILE"
success "URLs saved to $URL_FILE"

# ------------------ GF Patterns ------------------
if command -v gf &>/dev/null && [ -s "$URL_FILE" ]; then
    log "Starting: gf_patterns"
    mkdir -p "$OUTPUT_DIR/gf"

    # Loop through all available gf patterns on system
    for pattern in $(gf -list); do
        # Main gf output
        cat "$URL_FILE" | gf "$pattern" > "$OUTPUT_DIR/gf/${pattern}.txt" 2>/dev/null || true

        # Debug/test file (parameters only, strip after '=')
        cat "$OUTPUT_DIR/gf/${pattern}.txt" | sed 's/=.*//g' | sort -u > "$OUTPUT_DIR/gf/${pattern}_params.txt"
    done

    success "GF patterns + param-stripped files saved in $OUTPUT_DIR/gf/"
fi

# ------------------ Port Scanning ------------------
log "Starting: port_scan"
section "Port Scanning"
if command -v nmap &>/dev/null; then
    nmap -Pn -T4 --top-ports 100 "$TARGET" -oN "$OUTPUT_DIR/nmap.txt"
    success "Nmap scan saved to $OUTPUT_DIR/nmap.txt"
else
    echo -e "${RED}[x] Nmap not installed${RESET}"
fi

# ------------------ HTTP Probing ------------------
log "Starting: http_probe"
section "HTTP Probing"
if command -v httpx &>/dev/null; then
    cat "$SUBDOMAIN_FILE" | httpx -status-code -title -silent -sr -o "$OUTPUT_DIR/httpx.txt"
    success "HTTP probe saved to $OUTPUT_DIR/httpx.txt"
fi

# ------------------ Vulnerability Scan (nuclei) ------------------
if command -v nuclei &>/dev/null && [ -s "$OUTPUT_DIR/httpx.txt" ]; then
    log "Starting: vuln_scan (nuclei)"
    cut -d' ' -f1 "$OUTPUT_DIR/httpx.txt" | nuclei -silent -o "$OUTPUT_DIR/nuclei.txt"
    success "Nuclei scan saved to $OUTPUT_DIR/nuclei.txt"
fi

# ------------------ Screenshots ------------------
log "Starting: screenshots"
section "Web Screenshots"
if command -v gowitness &>/dev/null; then
    gowitness file -f "$SUBDOMAIN_FILE" -P "$OUTPUT_DIR/screenshots"
    success "Screenshots saved to $OUTPUT_DIR/screenshots/"
elif command -v aquatone &>/dev/null; then
    cat "$SUBDOMAIN_FILE" | aquatone -out "$OUTPUT_DIR/aquatone"
    success "Screenshots saved to $OUTPUT_DIR/aquatone/"
else
    echo -e "${RED}[x] gowitness/aquatone not installed${RESET}"
fi

echo -e "${GREEN}OSINT Scan Complete! Results in $OUTPUT_DIR${RESET}"

# Generate comprehensive report
generate_report() {
    log SECTION "Generating Report"
    local rep="$OUTPUT_DIR/report.html"
    
    local sub_count=$(wc -l < "$OUTPUT_DIR/subdomains/all.txt" 2>/dev/null || echo 0)
    local ip_count=$(wc -l < "$OUTPUT_DIR/ips/all.txt" 2>/dev/null || echo 0)
    local url_count=$(wc -l < "$OUTPUT_DIR/urls/all.txt" 2>/dev/null || echo 0)
    local live_count=$(wc -l < "$OUTPUT_DIR/recon/live.txt" 2>/dev/null || echo 0)
    local vuln_count=$(wc -l < "$OUTPUT_DIR/vulns/nuclei.txt" 2>/dev/null || echo 0)
    
    cat > "$rep" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OSINT Report - $TARGET</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f4f4f4; }
        .container { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #007acc; padding-bottom: 10px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-card { background: #007acc; color: white; padding: 20px; border-radius: 5px; text-align: center; }
        .stat-number { font-size: 2em; font-weight: bold; }
        .section { margin: 30px 0; }
        .section h2 { color: #007acc; border-left: 4px solid #007acc; padding-left: 10px; }
        pre { background: #f8f8f8; padding: 15px; border-radius: 5px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="container">
        <h1>OSINT Report for $TARGET</h1>
        <p>Generated on: $(date)</p>
        <p>Results directory: $OUTPUT_DIR</p>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">$sub_count</div>
                <div>Subdomains</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$ip_count</div>
                <div>IP Addresses</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$url_count</div>
                <div>URLs</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$live_count</div>
                <div>Live Hosts</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$vuln_count</div>
                <div>Vulnerabilities</div>
            </div>
        </div>

        <div class="section">
            <h2>Top Subdomains</h2>
            <pre>$(head -10 "$OUTPUT_DIR/subdomains/all.txt" 2>/dev/null || echo "No subdomains found")</pre>
        </div>

        <div class="section">
            <h2>DNS Information</h2>
            <h3>A Records</h3>
            <pre>$(cat "$OUTPUT_DIR/dns/A.txt" 2>/dev/null || echo "No A records")</pre>
            
            <h3>MX Records</h3>
            <pre>$(cat "$OUTPUT_DIR/dns/MX.txt" 2>/dev/null || echo "No MX records")</pre>
            
            <h3>TXT Records</h3>
            <pre>$(cat "$OUTPUT_DIR/dns/TXT.txt" 2>/dev/null || echo "No TXT records")</pre>
        </div>

        <div class="section">
            <h2>Top Vulnerabilities</h2>
            <pre>$(head -5 "$OUTPUT_DIR/vulns/nuclei.txt" 2>/dev/null || echo "No vulnerabilities found")</pre>
        </div>
    </div>
</body>
</html>
EOF
    
    log SUCCESS "Report generated: $rep"
}

# Main execution flow
main() {
    if [[ $# -lt 1 ]]; then
        echo "Usage: $0 <domain>"
        exit 1
    fi
    
    # Check for required tools first
    check_tools
    
    log SECTION "Starting OSINT Scan for: $TARGET"
    echo -e "${MAGENTA}========================================${NC}"
    echo -e "${MAGENTA}        ENHANCED OSINT SCANNER         ${NC}"
    echo -e "${MAGENTA}========================================${NC}"
    
    # Execute all functions with timing
    local start_time=$(date +%s)
    
    declare -a functions=(
        whois_lookup
        subdomain_enum
        dns_enum
        ip_collection
        url_discovery
        active_recon
        vuln_scan
        screenshot
        generate_report
    )
    
    for func in "${functions[@]}"; do
        local func_start=$(date +%s)
        log PROGRESS "Starting: $func"
        $func
        local func_end=$(date +%s)
        log DEBUG "$func completed in $((func_end - func_start)) seconds"
    done
    
    local end_time=$(date +%s)
    local total_time=$((end_time - start_time))
    
    echo -e "${MAGENTA}========================================${NC}"
    log SUCCESS "Scan completed in $total_time seconds!"
    log SUCCESS "Results saved to: $OUTPUT_DIR"
    echo -e "${MAGENTA}========================================${NC}"
}

# Error handling and cleanup
trap 'log ERROR "Script interrupted by user"; exit 1' INT TERM
trap 'rm -f "$OUTPUT_DIR"/*.tmp 2>/dev/null; exit' EXIT

main "$@"

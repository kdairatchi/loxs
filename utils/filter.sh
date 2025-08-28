#!/bin/bash
# ABOUTME: Enhanced automated bug bounty reconnaissance script with modern tools integration
# ABOUTME: Consolidates security scanning tools including katana, urlfinder, gf patterns, nuclei, and custom payload testing
## Enhanced by Doctor K's security research team

# Prevent gf alias conflicts (unalias gf in case GitHub alias is interfering)
unalias gf 2>/dev/null || true

scriptDir=$(dirname "$(readlink -f "$0")")
baseDir=$PWD
lastNotified=0
thorough=true
notify=true
overwrite=false
verbose=false
use_passive_only=false

# Source utility scripts if they exist
if [ -f "./utils/screenshotReport.sh" ]; then
    source "./utils/screenshotReport.sh"
fi

# Verbose logging function
function verbose_log {
    if [ "$verbose" = true ]; then
        echo "[VERBOSE] $1" | tee -a "${LOG_FILE:-/dev/null}"
    fi
}

# Error logging function
function error_log {
    echo "[ERROR] $1" | tee -a "${LOG_FILE:-/dev/null}" >&2
}

# Success logging function
function success_log {
    echo "[SUCCESS] $1" | tee -a "${LOG_FILE:-/dev/null}"
}

function notify {
    if [ "$notify" = true ]
    then
        if [ $(($(date +%s) - lastNotified)) -le 3 ]
        then
            echo "[!] Notifying too quickly, sleeping to avoid skipped notifications..."
            sleep 3
        fi

        # Format string to escape special characters and send message through Telegram API.
        if [ -z "$DOMAIN" ]
        then
            message=`echo -ne "*BugBountyScanner:* $1" | sed 's/[^a-zA-Z 0-9*_]/\\\\&/g'`
        else
            message=`echo -ne "*BugBountyScanner [$DOMAIN]:* $1" | sed 's/[^a-zA-Z 0-9*_]/\\\\&/g'`
        fi
    
        curl -s -X POST "https://api.telegram.org/bot$telegram_api_key/sendMessage" -d chat_id="$telegram_chat_id" -d text="$message" -d parse_mode="MarkdownV2" &> /dev/null
        lastNotified=$(date +%s)
    fi
}

for arg in "$@"
do
    case $arg in
        -h|--help)
        echo "Enhanced BugBountyHunter - Modern Automated Bug Bounty reconnaissance script"
        echo " "
        echo "$0 [options]"
        echo " "
        echo "options:"
        echo "-h, --help                    show brief help"
        echo "-t, --toolsdir <dir>          tools directory (no trailing /), defaults to '/opt'"
        echo "-q, --quick                   perform quick recon only (default: false)"
        echo "-d, --domain <domain>         top domain to scan, can take multiple"
        echo "-o, --outputdirectory <dir>   parent output directory, defaults to current directory (subfolders will be created per domain)"
        echo "-w, --overwrite               overwrite existing files. Skip steps with existing files if not provided (default: false)"
        echo "-v, --verbose                 enable verbose output (default: false)"
        echo "-p, --passive-only            use only passive reconnaissance techniques (default: false)"
        echo " "
        echo "Features:"
        echo "- Modern Katana crawler with proper flags"
        echo "- URLfinder for passive URL discovery"
        echo "- GF pattern matching (auto-unalias gf)"
        echo "- Improved error handling and logging"
        echo "- Better tool integration and performance"
        echo " "
        echo "Note: 'ToolsDir', as well as your 'telegram_api_key' and 'telegram_chat_id' can be defined in .env or through (Docker) environment variables."
        echo " "
        echo "example:"
        echo "$0 --quick -d google.com -d uber.com -t /opt --verbose"
        exit 0
        ;;
        -q|--quick)
        thorough=false
        shift
        ;;
        -d|--domain)
        domainargs+=("$2")
        shift
        shift
        ;;
        -t|--toolsdir)
        toolsDir="$2"
        shift
        shift
        ;;
        -o|--outputdirectory)
        baseDir="$2"
        shift
        shift
        ;;
        -w|--overwrite)
        overwrite=true
        shift
        ;;
        -v|--verbose)
        verbose=true
        shift
        ;;
        -p|--passive-only)
        use_passive_only=true
        shift
    esac
done

if [ -f "$scriptDir/.env" ]
then
    set -a
    . .env
    set +a
fi

if [ -z "$telegram_api_key" ] || [ -z "$telegram_chat_id" ]
then
    echo "[i] \$telegram_api_key and \$telegram_chat_id variables not found, disabling notifications..."
    notify=false
fi

if [ ! -d "$baseDir" ]
then
    read -r -N 1 -p "[?] Provided output directory \"$baseDir\" does not exist, create it? [Y/N] "
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]
    then
        exit 1
    fi
    mkdir -p "$baseDir"
fi

if [ "${#domainargs[@]}" -ne 0 ]
then
    IFS=', ' read -r -a DOMAINS <<< "${domainargs[@]}"
else
    read -r -p "[?] What's the target domain(s)? E.g. \"domain.com,domain2.com\". DOMAIN: " domainsresponse
    IFS=', ' read -r -a DOMAINS <<< "$domainsresponse"  
fi

if [ -z "$toolsDir" ]
then
    echo "[i] \$toolsDir variable not defined in .env, defaulting to /opt..."
    toolsDir="/opt"
fi

# Ensure Go tools are in PATH
echo "$PATH" | grep -q "$HOME/go/bin" || export PATH=$PATH:$HOME/go/bin
echo "$PATH" | grep -q "/usr/local/go/bin" || export PATH=$PATH:/usr/local/go/bin

# Enhanced dependency check
function check_tool_dependency {
    local tool=$1
    local install_cmd=$2
    
    if command -v "$tool" &> /dev/null; then
        verbose_log "Tool $tool found: $(which $tool)"
        return 0
    else
        error_log "Tool $tool not found"
        if [ -n "$install_cmd" ]; then
            echo "[*] Installing $tool with: $install_cmd"
            eval "$install_cmd"
        fi
        return 1
    fi
}

# Check essential dependencies
missing_tools=()
check_tool_dependency "nuclei" "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" || missing_tools+=("nuclei")
check_tool_dependency "katana" "go install github.com/projectdiscovery/katana/cmd/katana@latest" || missing_tools+=("katana")
check_tool_dependency "urlfinder" "go install -v github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest" || missing_tools+=("urlfinder")
check_tool_dependency "httpx" "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest" || missing_tools+=("httpx")
check_tool_dependency "gf" "go install github.com/tomnomnom/gf@latest" || missing_tools+=("gf")
check_tool_dependency "gau" "go install github.com/lc/gau/v2/cmd/gau@latest" || missing_tools+=("gau")
check_tool_dependency "qsreplace" "go install github.com/tomnomnom/qsreplace@latest" || missing_tools+=("qsreplace")
check_tool_dependency "subjack" "go install github.com/haccer/subjack@latest" || missing_tools+=("subjack")
check_tool_dependency "ffuf" "go install github.com/ffuf/ffuf/v2@latest" || missing_tools+=("ffuf")
check_tool_dependency "amass" "" || missing_tools+=("amass")
check_tool_dependency "nrich" "" || missing_tools+=("nrich")

if [ ${#missing_tools[@]} -gt 0 ]; then
    echo "[*] Missing tools detected: ${missing_tools[*]}"
    echo "[*] Running setup script to install dependencies..."
    bash "$scriptDir/setup.sh" -t "$toolsDir"
else
    success_log "All essential dependencies found."
fi

cd "$baseDir" || { echo "Something went wrong"; exit 1; }

# Enable logging for stdout and stderr (timestamp format [dd/mm/yy hh:mm:ss])
LOG_FILE="./BugBountyScanner-$(date +'%Y%m%d-%T').log"
exec > >(while read -r line; do printf '%s %s\n' "[$(date +'%D %T')]" "$line" | tee -a "${LOG_FILE}"; done) 2>&1

echo "[*] STARTING RECON."
notify "Starting recon on *${#DOMAINS[@]}* domains."

for DOMAIN in "${DOMAINS[@]}"
do
    mkdir -p "$DOMAIN"
    cd "$DOMAIN" || { echo "Something went wrong"; exit 1; }

    cp -r "$scriptDir/dist" .

    echo "[*] RUNNING RECON ON $DOMAIN."
    notify "Starting recon on $DOMAIN. Enumerating subdomains with Amass..."

    if [ ! -f "domains-$DOMAIN.txt" ] || [ "$overwrite" = true ]
    then
        echo "[*] RUNNING AMASS..."
        amass enum --passive -d "$DOMAIN" -o "domains-$DOMAIN.txt"
        notify "Amass completed! Identified *$(wc -l < "domains-$DOMAIN.txt")* subdomains. Resolving IP addresses..."
    else
        echo "[-] SKIPPING AMASS"
    fi

    if [ ! -f "ip-addresses-$DOMAIN.txt" ] || [ "$overwrite" = true ]
    then
        echo "[*] RESOLVING IP ADDRESSES FROM HOSTS..."
        while read -r hostname; do
            dig "$hostname" +short >> "dig.txt"
        done < "domains-$DOMAIN.txt"
        grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' "dig.txt" | sort -u > "ip-addresses-$DOMAIN.txt" && rm "dig.txt"
        notify "Resolving done! Enriching *$(wc -l < "ip-addresses-$DOMAIN.txt")* IP addresses with Shodan data..."
    else
        echo "[-] SKIPPING RESOLVING HOST IP ADDRESSES"
    fi

    if [ ! -f "nrich-$DOMAIN.txt" ] || [ "$overwrite" = true ]
    then
        echo "[*] ENRICHING IP ADDRESS DATA WITH SHODAN..."
        nrich "ip-addresses-$DOMAIN.txt" > "nrich-$DOMAIN.txt"
        notify "IP addresses enriched! Make sure to give that a manual look. Getting live domains with HTTPX..."
    else
        echo "[-] SKIPPING IP ENRICHMENT"
    fi

    if [ ! -f "livedomains-$DOMAIN.txt" ] || [ "$overwrite" = true ]
    then
        echo "[*] RUNNING ENHANCED HTTPX PROBE..."
        verbose_log "Starting HTTP probing on $(wc -l < "domains-$DOMAIN.txt" 2>/dev/null || echo 0) domains"
        
        # Enhanced httpx configuration with better coverage and error handling
        httpx -list "domains-$DOMAIN.txt" \
            -silent \
            -no-color \
            -title \
            -content-length \
            -web-server \
            -tech-detect \
            -status-code \
            -response-time \
            -ports 80,8080,443,8443,3000,8000,8888,9000 \
            -threads 50 \
            -timeout 10 \
            -retries 2 \
            -rate-limit 100 \
            -follow-redirects \
            -json \
            -output "httpx-$DOMAIN.json" 2>/dev/null || touch "httpx-$DOMAIN.json"
        
        # Process JSON output and create both detailed and simple lists
        if [ -f "httpx-$DOMAIN.json" ] && [ -s "httpx-$DOMAIN.json" ]; then
            # Extract URLs for compatibility
            jq -r '.url' "httpx-$DOMAIN.json" 2>/dev/null | sort -u > "livedomains-$DOMAIN.txt" || \
            grep -o '"url":"[^"]*"' "httpx-$DOMAIN.json" | cut -d'"' -f4 | sort -u > "livedomains-$DOMAIN.txt" || \
            touch "livedomains-$DOMAIN.txt"
            
            # Create human-readable summary
            jq -r '[.url, .status_code, .title, .webserver, .tech] | @tsv' "httpx-$DOMAIN.json" 2>/dev/null > "httpx-$DOMAIN.txt" || \
            cp "httpx-$DOMAIN.json" "httpx-$DOMAIN.txt" 2>/dev/null
        else
            touch "livedomains-$DOMAIN.txt" "httpx-$DOMAIN.txt"
        fi
        
        live_count=$(wc -l < "livedomains-$DOMAIN.txt" 2>/dev/null || echo 0)
        success_log "HTTPX probe completed: $live_count live endpoints discovered"
        notify "Enhanced HTTPX completed. *$live_count* endpoints are alive with detailed technology fingerprinting. Checking for hijackable subdomains with SubJack..."
    else
        echo "[-] SKIPPING ENHANCED HTTPX PROBE"
    fi

    if [ ! -f "subjack-$DOMAIN.txt" ] || [ "$overwrite" = true ]
    then
        echo "[*] RUNNING SUBJACK..."
        subjack -w "domains-$DOMAIN.txt" -t 100 -c "$toolsDir/subjack/fingerprints.json" -o "subjack-$DOMAIN.txt" -a
        if [ -f "subjack-$DOMAIN.txt" ]; then
            echo "[+] HIJACKABLE SUBDOMAINS FOUND!"
            notify "SubJack completed. One or more hijackable subdomains found!"
            notify "Hijackable domains: $(cat "subjack-$DOMAIN.txt")"
            notify "Gathering live page screenshots with aquatone..."
        else
            echo "[-] NO HIJACKABLE SUBDOMAINS FOUND."
            notify "No hijackable subdomains found. Gathering live page screenshots with aquatone..."
        fi
    else
        echo "[-] SKIPPING SUBJACK"
    fi

    if [ ! -f "aquatone_report.html" ] || [ "$overwrite" = true ]
    then
        echo "[*] RUNNING AQUATONE..."
        cat livedomains-$DOMAIN.txt | aquatone -ports medium
        generate_screenshot_report "$DOMAIN"
        notify "Aquatone completed! Took *$(find screenshots/* -maxdepth 0 | wc -l)* screenshots. Getting Wayback Machine path list with GAU..."
    else
        echo "[-] SKIPPING AQUATONE"
    fi

    if [ ! -f "WayBack-$DOMAIN.txt" ] || [ "$overwrite" = true ]
    then
        echo "[*] RUNNING GAU..."
        # Get ONLY Wayback URLs with parameters to prevent clutter
        gau -subs -providers wayback -o "gau-$DOMAIN.txt" "$DOMAIN"
        grep '?' < "gau-$DOMAIN.txt" | qsreplace -a > "WayBack-$DOMAIN.txt"
        rm "gau-$DOMAIN.txt"
        notify "GAU completed. Got *$(wc -l < "WayBack-$DOMAIN.txt")* paths."
    else
        echo "[-] SKIPPING GAU"
    fi

    if [ "$thorough" = true ] ; then
        if [ ! -f "nuclei-$DOMAIN.txt" ] || [ "$overwrite" = true ]
        then
            echo "[*] RUNNING ENHANCED NUCLEI SCAN..."
            notify "Detecting known vulnerabilities with enhanced Nuclei configuration..."
            verbose_log "Starting Nuclei scan on $(wc -l < "livedomains-$DOMAIN.txt" 2>/dev/null || echo 0) live domains"
            
            # Update nuclei templates before scanning
            echo "[*] Updating Nuclei templates..."
            nuclei -update-templates -silent 2>/dev/null || verbose_log "Template update failed or skipped"
            
            # Enhanced nuclei configuration with modern flags
            nuclei_cmd="nuclei -list \"livedomains-$DOMAIN.txt\" \
                -c 100 \
                -rl 150 \
                -timeout 10 \
                -retries 2 \
                -severity low,medium,high,critical \
                -exclude-tags intrusive,dos,fuzzing \
                -include-tags cve,misconfig,exposure,vulnerability \
                -stats \
                -silent \
                -jsonl \
                -output \"nuclei-$DOMAIN.jsonl\""
            
            verbose_log "Running: $nuclei_cmd"
            eval "$nuclei_cmd" 2>/dev/null || touch "nuclei-$DOMAIN.jsonl"
            
            # Convert JSONL to readable format for compatibility
            if [ -f "nuclei-$DOMAIN.jsonl" ]; then
                jq -r '[.timestamp, .info.severity, .info.name, .matched_at] | @tsv' "nuclei-$DOMAIN.jsonl" 2>/dev/null > "nuclei-$DOMAIN.txt" || \
                cat "nuclei-$DOMAIN.jsonl" | grep -o '"matched-at":"[^"]*"\|"severity":"[^"]*"\|"name":"[^"]*"' | paste - - - > "nuclei-$DOMAIN.txt" 2>/dev/null || \
                cp "nuclei-$DOMAIN.jsonl" "nuclei-$DOMAIN.txt" 2>/dev/null
            else
                touch "nuclei-$DOMAIN.txt"
            fi
            
            # Enhanced vulnerability analysis with better counting
            if [ -f "nuclei-$DOMAIN.txt" ] && [ -s "nuclei-$DOMAIN.txt" ]; then
                total_issues=$(wc -l < "nuclei-$DOMAIN.txt" 2>/dev/null || echo 0)
                highIssues=$(grep -ic 'high' "nuclei-$DOMAIN.txt" 2>/dev/null || echo 0)
                critIssues=$(grep -ic 'critical' "nuclei-$DOMAIN.txt" 2>/dev/null || echo 0)
                mediumIssues=$(grep -ic 'medium' "nuclei-$DOMAIN.txt" 2>/dev/null || echo 0)
                lowIssues=$(grep -ic 'low' "nuclei-$DOMAIN.txt" 2>/dev/null || echo 0)
                
                success_log "Nuclei scan completed: Total=$total_issues, Critical=$critIssues, High=$highIssues, Medium=$mediumIssues, Low=$lowIssues"
                
                if [ "$critIssues" -gt 0 ]; then
                    notify "🚨 CRITICAL: Nuclei found *$total_issues* issues including *$critIssues* CRITICAL and *$highIssues* HIGH severity vulnerabilities!"
                elif [ "$highIssues" -gt 0 ]; then
                    notify "⚠️ HIGH RISK: Nuclei found *$total_issues* issues including *$highIssues* HIGH severity vulnerabilities!"
                elif [ "$mediumIssues" -gt 0 ]; then
                    notify "⚠️ Nuclei found *$total_issues* issues including *$mediumIssues* MEDIUM severity vulnerabilities."
                else
                    notify "✅ Nuclei completed with *$total_issues* low-severity findings."
                fi
            else
                notify "✅ Nuclei scan completed - No significant vulnerabilities detected."
                success_log "Nuclei scan found no issues"
            fi
        else
            echo "[-] SKIPPING NUCLEI"
        fi

        if [ ! -d "ffuf" ] || [ "$overwrite" = true ]
        then
                echo "[*] RUNNING FFUF..."
		mkdir ffuf
		cd ffuf || { echo "Something went wrong"; exit 1; }

		while read -r dname;
		do
    			filename=$(echo "${dname##*/}" | sed 's/:/./g')
    			ffuf -w "$toolsDir/wordlists/tempfiles.txt" -u "$dname/FUZZ" -mc 200-299 -maxtime 180 -o "ffuf-$filename.csv" -of csv
		done < "../livedomains-$DOMAIN.txt"

        # Remove all files with only a header row
        find . -type f -size -1c -delete

        # Count the number of files (lines in the ffuf files, excluding the header row for each file) and sum into variable
        ffufFiles=$(find . -type f -exec wc -l {} + | sed '$d' | awk '{sum+=$1-1} END{print sum}')

		if [ "$ffufFiles" -gt 0 ]
        then
    			notify "FFUF completed. Got *$ffufFiles* files. Spidering paths with GoSpider..."
    			cd .. || { echo "Something went wrong"; exit 1; }
		else
    			notify "FFUF completed. No temporary files identified. Spidering paths with GoSpider..."
    			cd .. || { echo "Something went wrong"; exit 1; }
    			rm -rf ffuf
		fi

            fi   
        else
            echo "[-] SKIPPING ffuf"
        fi

        if [ ! -f "paths-$DOMAIN.txt" ] || [ "$overwrite" = true ]
        then
            echo "[*] RUNNING ENHANCED WEB CRAWLING (KATANA)..."
            verbose_log "Starting active crawling with Katana"
            
            # Use modern Katana crawler with proper flags
            if [ "$use_passive_only" = true ]; then
                echo "[*] Passive mode: skipping active crawling"
                cp "WayBack-$DOMAIN.txt" "tmp-Katana-$DOMAIN.txt" 2>/dev/null || touch "tmp-Katana-$DOMAIN.txt"
            else
                echo "[*] Running Katana crawler with enhanced configuration..."
                katana -list "livedomains-$DOMAIN.txt" \
                    -d 3 \
                    -jc \
                    -fx \
                    -xhr \
                    -timeout 10 \
                    -retry 2 \
                    -rl 150 \
                    -c 25 \
                    -mrs 1048576 \
                    -silent \
                    -o "tmp-Katana-$DOMAIN.txt" 2>/dev/null || touch "tmp-Katana-$DOMAIN.txt"
                
                verbose_log "Katana crawling completed with $(wc -l < "tmp-Katana-$DOMAIN.txt" 2>/dev/null || echo 0) URLs found"
            fi
            
            # Filter and process crawled URLs
            if [ -f "tmp-Katana-$DOMAIN.txt" ]; then
                grep "$DOMAIN" "tmp-Katana-$DOMAIN.txt" | sort -u | qsreplace -a > "tmp-GoSpider-$DOMAIN.txt"
            else
                touch "tmp-GoSpider-$DOMAIN.txt"
            fi
            katana_count=$(wc -l < "tmp-GoSpider-$DOMAIN.txt" 2>/dev/null || echo 0)
            notify "Katana completed. Crawled *$katana_count* endpoints. Getting interesting endpoints and parameters..."
            success_log "Katana found $katana_count domain-specific URLs"

            ## Enrich GoSpider list with parameters from GAU/WayBack. Disregard new GAU endpoints to prevent clogging with unreachable endpoints (See Issue #24).
            # Get only endpoints from GoSpider list (assumed to be live), disregard parameters, and append ? for grepping
            sed "s/\?.*//" "tmp-GoSpider-$DOMAIN.txt" | sort -u | sed -e 's/$/\?/' > "tmp-LivePathsQuery-$DOMAIN.txt"
            # Find common endpoints containing (hopefully new and interesting) parameters from GAU/Wayback list
            grep -f "tmp-LivePathsQuery-$DOMAIN.txt" "WayBack-$DOMAIN.txt" > "tmp-LiveWayBack-$DOMAIN.txt"
            # Merge new parameters with GoSpider list and get only unique endpoints
            cat "tmp-LiveWayBack-$DOMAIN.txt" "tmp-GoSpider-$DOMAIN.txt" | sort -u | qsreplace -a > "paths-$DOMAIN.txt"
            rm -f "tmp-LivePathsQuery-$DOMAIN.txt" "tmp-LiveWayBack-$DOMAIN.txt" "tmp-GoSpider-$DOMAIN.txt" "tmp-Katana-$DOMAIN.txt"
            
            total_paths=$(wc -l < "paths-$DOMAIN.txt" 2>/dev/null || echo 0)
            success_log "Total unique paths collected: $total_paths"
        else
            echo "[-] SKIPPING ENHANCED WEB CRAWLING"
        fi

        if [ ! -d "check-manually" ] || [ "$overwrite" = true ]
        then
            echo "[*] GETTING INTERESTING PARAMETERS WITH ENHANCED GF PATTERNS..."
            mkdir -p "check-manually"
            verbose_log "Starting GF pattern matching on $(wc -l < "paths-$DOMAIN.txt" 2>/dev/null || echo 0) paths"
            
            # Ensure gf patterns are available
            if [ ! -d "$HOME/.gf" ] || [ -z "$(ls -A "$HOME/.gf" 2>/dev/null)" ]; then
                error_log "GF patterns not found, attempting to install..."
                mkdir -p "$HOME/.gf"
                if command -v git &> /dev/null; then
                    git clone -q https://github.com/1ndianl33t/Gf-Patterns.git /tmp/gf-patterns 2>/dev/null || true
                    cp /tmp/gf-patterns/*.json "$HOME/.gf/" 2>/dev/null || true
                    rm -rf /tmp/gf-patterns 2>/dev/null || true
                    success_log "GF patterns installed successfully"
                fi
            fi
            
            # Use GF to identify "suspicious" endpoints that may be vulnerable (with error handling)
            echo "[*] Running GF pattern matching..."
            gf ssrf < "paths-$DOMAIN.txt" > "check-manually/server-side-request-forgery.txt" 2>/dev/null || touch "check-manually/server-side-request-forgery.txt"
            gf xss < "paths-$DOMAIN.txt" > "check-manually/cross-site-scripting.txt" 2>/dev/null || touch "check-manually/cross-site-scripting.txt"
            gf redirect < "paths-$DOMAIN.txt" > "check-manually/open-redirect.txt" 2>/dev/null || touch "check-manually/open-redirect.txt"
            gf rce < "paths-$DOMAIN.txt" > "check-manually/rce.txt" 2>/dev/null || touch "check-manually/rce.txt"
            gf idor < "paths-$DOMAIN.txt" > "check-manually/insecure-direct-object-reference.txt" 2>/dev/null || touch "check-manually/insecure-direct-object-reference.txt"
            gf sqli < "paths-$DOMAIN.txt" > "check-manually/sql-injection.txt" 2>/dev/null || touch "check-manually/sql-injection.txt"
            gf lfi < "paths-$DOMAIN.txt" > "check-manually/local-file-inclusion.txt" 2>/dev/null || touch "check-manually/local-file-inclusion.txt"
            gf ssti < "paths-$DOMAIN.txt" > "check-manually/server-side-template-injection.txt" 2>/dev/null || touch "check-manually/server-side-template-injection.txt"
            
            # Additional modern vulnerability patterns
            gf debug < "paths-$DOMAIN.txt" > "check-manually/debug-parameters.txt" 2>/dev/null || touch "check-manually/debug-parameters.txt"
            gf interestingsubs < "paths-$DOMAIN.txt" > "check-manually/interesting-subdomains.txt" 2>/dev/null || touch "check-manually/interesting-subdomains.txt"
            gf cors < "paths-$DOMAIN.txt" > "check-manually/cors-misconfiguration.txt" 2>/dev/null || touch "check-manually/cors-misconfiguration.txt"
            
            # Count results
            pattern_matches=$(find check-manually/ -name "*.txt" -exec wc -l {} + 2>/dev/null | tail -1 | awk '{print $1}' || echo 0)
            total_paths_analyzed=$(wc -l < "paths-$DOMAIN.txt" 2>/dev/null || echo 0)
            
            success_log "GF pattern matching completed: $pattern_matches potentially vulnerable URLs identified from $total_paths_analyzed total paths"
            notify "Enhanced GF analysis completed! Analyzed *$total_paths_analyzed* paths, identified *$pattern_matches* potentially exploitable endpoints across $(ls check-manually/*.txt 2>/dev/null | wc -l || echo 0) vulnerability categories. Starting automated vulnerability testing..."
            verbose_log "Pattern matching results: SSRF=$(wc -l < check-manually/server-side-request-forgery.txt 2>/dev/null || echo 0), XSS=$(wc -l < check-manually/cross-site-scripting.txt 2>/dev/null || echo 0), SQLi=$(wc -l < check-manually/sql-injection.txt 2>/dev/null || echo 0), LFI=$(wc -l < check-manually/local-file-inclusion.txt 2>/dev/null || echo 0)"
        else
            echo "[-] SKIPPING ENHANCED GF PATTERN MATCHING"
        fi

        if [ ! -f "potential-ssti.txt" ] || [ "$overwrite" = true ]
        then
            echo "[*] TESTING FOR SSTI..."
            qsreplace "BugBountyScanner{{9*9}}" < "check-manually/server-side-template-injection.txt" | \
            xargs -I % -P 100 sh -c 'curl -s "%" 2>&1 | grep -q "BugBountyScanner81" && echo "[+] Found endpoint likely to be vulnerable to SSTI: %" && echo "%" >> potential-ssti.txt'
            if [ -f "potential-ssti.txt" ]; then
                notify "Identified *$(wc -l < potential-ssti.txt)* endpoints potentially vulnerable to SSTI! Testing for Local File Inclusion..."
            else
                notify "No SSTI found. Testing for Local File Inclusion..."
            fi
        else
            echo "[-] SKIPPING TEST FOR SSTI"
        fi

        if [ ! -f "potential-lfi.txt" ] || [ "$overwrite" = true ]
        then
            echo "[*] TESTING FOR (*NIX) LFI..."
            qsreplace "/etc/passwd" < "check-manually/local-file-inclusion.txt" | \
            xargs -I % -P 100 sh -c 'curl -s "%" 2>&1 | grep -q "root:x:" && echo "[+] Found endpoint likely to be vulnerable to LFI: %" && echo "%" >> potential-lfi.txt'
            if [ -f "potential-lfi.txt" ]; then
                notify "Identified *$(wc -l < potential-lfi.txt)* endpoints potentially vulnerable to LFI! Testing for Open Redirections..."
            else
                notify "No LFI found. Testing for Open Redirections..."
            fi
        else
            echo "[-] SKIPPING TEST FOR (*NIX) LFI"
        fi

        if [ ! -f "potential-or.txt" ] || [ "$overwrite" = true ]
        then
            echo "[*] TESTING FOR OPEN REDIRECTS..."
            qsreplace "https://www.testing123.com" < "check-manually/open-redirect.txt" | \
            xargs -I % -P 100 sh -c 'curl -s "%" 2>&1 | grep -q "Location: https://www.testing123.com" && echo "[+] Found endpoint likely to be vulnerable to OR: %" && echo "%" >> potential-or.txt'
            if [ -f "potential-or.txt" ]; then
                notify "Identified *$(wc -l < potential-or.txt)* endpoints potentially vulnerable to open redirects! Resolving IP Addresses..."
            else
                notify "No open redirects found. Starting Nmap for *$(wc -l < "ip-addresses-$DOMAIN.txt")* IP addresses..."
            fi
        else
            echo "[-] SKIPPING TEST FOR OPEN REDIRECTS"
        fi

        if [ ! -d "nmap" ] || [ "$overwrite" = true ]
        then
            echo "[*] RUNNING NMAP (TOP 1000 TCP)..."
            mkdir nmap
            nmap -T4 -sV --open --source-port 53 --max-retries 3 --host-timeout 15m -iL "ip-addresses-$DOMAIN.txt" -oA nmap/nmap-tcp
            grep Port < nmap/nmap-tcp.gnmap | cut -d' ' -f2 | sort -u > nmap/tcpips.txt
            notify "Nmap TCP done! Identified *$(grep -c "Port" < "nmap/nmap-tcp.gnmap")* IPs with ports open. Starting Nmap UDP/SNMP scan for *$(wc -l < "nmap/tcpips.txt")* IP addresses..."

            echo "[*] RUNNING NMAP (SNMP UDP)..."
            nmap -T4 -sU -sV -p 161 --open --source-port 53 -iL nmap/tcpips.txt -oA nmap/nmap-161udp
            rm nmap/tcpips.txt
            notify "Nmap UDP done! Identified *$(grep "Port" < "nmap/nmap-161udp.gnmap" | grep -cv "filtered")* IPS with SNMP port open."
        else
            echo "[-] SKIPPING NMAP"
        fi
    

    cd ..
    echo "[+] DONE SCANNING $DOMAIN."
    notify "Recon on $DOMAIN finished."

done

echo "[+] DONE! :D"
notify "Recon finished! Go hack em!"

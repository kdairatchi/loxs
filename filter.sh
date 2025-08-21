#!/bin/bash

set -euo pipefail

# Colors for better output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Global variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="output"
TOOLS_DIR="$HOME/tools"
GO_BIN="$HOME/go/bin"

# Progress tracking
TOTAL_STEPS=0
CURRENT_STEP=0

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_progress() {
    CURRENT_STEP=$((CURRENT_STEP + 1))
    local progress_bar=""
    local completed=$((CURRENT_STEP * 20 / TOTAL_STEPS))
    
    # Create simple progress bar
    for ((i=1; i<=20; i++)); do
        if [ $i -le $completed ]; then
            progress_bar="${progress_bar}█"
        else
            progress_bar="${progress_bar}░"
        fi
    done
    
    local percentage=$((CURRENT_STEP * 100 / TOTAL_STEPS))
    echo -e "${PURPLE}[PROGRESS ${percentage}%]${NC} ${progress_bar} Step $CURRENT_STEP/$TOTAL_STEPS: $1"
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to validate regex patterns before using them
validate_pattern() {
    local pattern="$1"
    
    # Quick syntax check for common issues
    if [ -z "$pattern" ]; then
        return 1
    fi
    
    # Check for unmatched brackets and parentheses
    local open_paren=$(echo "$pattern" | grep -o '(' | wc -l)
    local close_paren=$(echo "$pattern" | grep -o ')' | wc -l)
    local open_bracket=$(echo "$pattern" | grep -o '\[' | wc -l)
    local close_bracket=$(echo "$pattern" | grep -o '\]' | wc -l)
    
    if [ "$open_paren" -ne "$close_paren" ] || [ "$open_bracket" -ne "$close_bracket" ]; then
        print_warning "Pattern has unmatched brackets/parentheses: $pattern"
        return 1
    fi
    
    # Test the pattern with a simple string to catch basic errors
    if echo "test=value&param=data" | timeout 5 grep -E "$pattern" >/dev/null 2>&1; then
        return 0
    elif echo "?test=value&param=data" | timeout 5 grep -E "$pattern" >/dev/null 2>&1; then
        return 0
    else
        print_warning "Pattern validation failed: $pattern"
        return 1
    fi
}

# Function to handle process timeouts and cleanup
handle_timeout() {
    local pid=$1
    local timeout=$2
    local description="$3"
    
    # Wait for process with timeout
    local count=0
    while kill -0 "$pid" 2>/dev/null && [ $count -lt "$timeout" ]; do
        sleep 1
        count=$((count + 1))
    done
    
    # Kill if still running
    if kill -0 "$pid" 2>/dev/null; then
        print_warning "$description timed out, terminating..."
        kill -TERM "$pid" 2>/dev/null
        sleep 2
        kill -KILL "$pid" 2>/dev/null
        return 1
    fi
    
    return 0
}

# Function to install Go tools
install_go_tool() {
    local tool_name="$1"
    local install_cmd="$2"
    
    if ! command_exists "$tool_name"; then
        print_status "Installing $tool_name..."
        if eval "$install_cmd"; then
            print_success "$tool_name installed successfully"
        else
            print_error "Failed to install $tool_name"
            return 1
        fi
    else
        print_success "$tool_name is already installed"
    fi
}

# Function to install Python tools
install_python_tool() {
    local tool_name="$1"
    local install_cmd="$2"
    
    if ! command_exists "$tool_name"; then
        print_status "Installing $tool_name..."
        if eval "$install_cmd"; then
            print_success "$tool_name installed successfully"
        else
            print_error "Failed to install $tool_name"
            return 1
        fi
    else
        print_success "$tool_name is already installed"
    fi
}

# Function to install all required tools
install_tools() {
    print_status "Checking and installing required tools..."
    
    # Ensure directories exist
    mkdir -p "$TOOLS_DIR" "$GO_BIN"
    
    # Add Go bin to PATH if not already there
    if [[ ":$PATH:" != *":$GO_BIN:"* ]]; then
        export PATH="$GO_BIN:$PATH"
    fi
    
    # Install Go-based tools
    install_go_tool "katana" "go install github.com/projectdiscovery/katana/cmd/katana@latest"
    install_go_tool "gf" "go install github.com/tomnomnom/gf@latest"
    install_go_tool "anew" "go install github.com/tomnomnom/anew@latest"
    install_go_tool "Gxss" "go install github.com/KathanP19/Gxss@latest"
    install_go_tool "kxss" "go install github.com/Emoe/kxss@latest"
    install_go_tool "subfinder" "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    install_go_tool "httpx" "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
    install_go_tool "waybackurls" "go install github.com/tomnomnom/waybackurls@latest"
    install_go_tool "gau" "go install github.com/lc/gau/v2/cmd/gau@latest"
    
    # Check for 'timeout' command
    if ! command_exists "timeout"; then
        print_warning "'timeout' command not found. Some operations may run indefinitely. Please install coreutils (e.g., 'brew install coreutils' on macOS, 'sudo apt-get install coreutils' on Debian/Ubuntu, 'sudo yum install coreutils' on CentOS/RHEL)."
    fi
    
    # Install gf patterns if gf is installed
    if command_exists "gf"; then
        if [ ! -d "$HOME/.gf" ]; then
            print_status "Installing gf patterns..."
            git clone https://github.com/1ndianl33t/Gf-Patterns "$HOME/.gf" || print_warning "Failed to clone gf patterns"
        fi
    fi
    
    print_success "Tool installation check completed"
}

# Function to validate URL
validate_url() {
    local url="$1"
    if [[ ! $url =~ ^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$ ]]; then
        print_error "Invalid URL format: $url"
        return 1
    fi
    return 0
}

# Function to normalize URL input
normalize_url() {
    local input="$1"
    local normalized_url
    
    # Remove trailing slash
    input="${input%/}"
    
    # Add https:// if no protocol is specified
    if [[ ! $input =~ ^https?:// ]]; then
        normalized_url="https://$input"
    else
        normalized_url="$input"
    fi
    
    echo "$normalized_url"
}

# Function to gather URLs with parallel processing
gather_urls() {
    local website_url="$1"
    local domain=$(echo "$website_url" | sed -e 's|^[^/]*//||' -e 's|/.*$||')
    local temp_file="$OUTPUT_DIR/temp_urls.txt"
    local temp_dir="$OUTPUT_DIR/temp"
    
    print_progress "Gathering URLs from multiple sources for $domain (parallel processing)"
    
    # Create temporary directory and files
    mkdir -p "$temp_dir"
    > "$temp_file"
    
    if command_exists "katana"; then
        print_status "Starting katana passive scan..."
        if command_exists "timeout"; then
            (echo "$website_url" | timeout 300 katana -ps -pss waybackarchive,commoncrawl,alienvault -f qurl -silent > "$temp_dir/katana_passive.txt" 2>/dev/null || print_warning "Katana passive scan had issues") &
        else
            (echo "$website_url" | katana waybackarchive,commoncrawl,alienvault -f qurl -silent > "$temp_dir/katana_passive.txt" 2>/dev/null || print_warning "Katana passive scan had issues") &
        fi
    fi
    
    # Method 2: Katana active crawling (background)
    if command_exists "katana"; then
        print_status "Starting katana active crawling..."
        if command_exists "timeout"; then
            (timeout 600 katana -u "$website_url" -d 3 -f qurl -c 50 > "$temp_dir/katana_active.txt" 2>/dev/null || print_warning "Katana active scan had issues") &
        else
            (katana -u "$website_url" -d 3 -f qurl -silent -c 50 > "$temp_dir/katana_active.txt" 2>/dev/null || print_warning "Katana active scan had issues") &
        fi
    fi
    
    # Method 3: Wayback URLs (background)
    if command_exists "waybackurls"; then
        print_status "Starting Wayback Machine fetch..."
        if command_exists "timeout"; then
            (echo "$domain" | timeout 180 waybackurls > "$temp_dir/wayback.txt" 2>/dev/null || print_warning "Waybackurls had issues") &
        else
            (echo "$domain" | waybackurls > "$temp_dir/wayback.txt" 2>/dev/null || print_warning "Waybackurls had issues") &
        fi
    fi
    
    # Method 4: GetAllUrls (GAU) (background)
    if command_exists "gau"; then
        print_status "Starting GAU fetch..."
        if command_exists "timeout"; then
            (echo "$domain" | gau --threads 20 --timeout 10 > "$temp_dir/gau.txt" 2>/dev/null || print_warning "GAU had issues") &
        else
            (echo "$domain" | gau --threads 20 > "$temp_dir/gau.txt" 2>/dev/null || print_warning "GAU had issues") &
        fi
    fi
    
    # Method 5: Subdomain enumeration + URL discovery (background)
    if command_exists "subfinder" && command_exists "httpx" && command_exists "katana"; then
        print_status "Starting subdomain enumeration..."
        if command_exists "timeout"; then
            (timeout 300 subfinder -d "$domain" -all | timeout 180 httpx -threads 50 | head -20 | while read -r subdomain; do
                echo "$subdomain" | timeout 60 katana -pss waybackarchive -f qurl -silent 2>/dev/null
            done > "$temp_dir/subdomains.txt" 2>/dev/null || print_warning "Subdomain enumeration had issues") &
        else
            (subfinder -d "$domain" -all | httpx -threads 50 | head -20 | while read -r subdomain; do
                echo "$subdomain" | katana  -pss waybackarchive -f qurl 2>/dev/null
            done > "$temp_dir/subdomains.txt" 2>/dev/null || print_warning "Subdomain enumeration had issues") &
        fi
    fi
    
    # Show progress while waiting
    local wait_count=0
    while [ $(jobs -r | wc -l) -gt 0 ] && [ $wait_count -lt 120 ]; do
        echo -ne "\rWaiting for URL gathering to complete... ${wait_count}s"
        sleep 5
        wait_count=$((wait_count + 5))
    done
    echo
    
    # Wait for all background jobs to complete (with timeout)
    print_status "Finalizing URL collection..."
    wait
    
    # Combine all results
    cat "$temp_dir"/*.txt > "$temp_file" 2>/dev/null || touch "$temp_file"
    
    # Enhanced deduplication and cleaning with multiple methods
    print_status "Optimizing URL list..."
    
    # Pre-filter valid URLs to reduce processing time
    grep -E '^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' "$temp_file" 2>/dev/null | \
        grep -v -E '\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|ttf|eot|pdf|zip|tar|gz)$' > "$OUTPUT_DIR/temp_filtered.txt" 2>/dev/null || touch "$OUTPUT_DIR/temp_filtered.txt"
    
    # Use uro if available, otherwise use custom deduplication
    if command_exists "uro" && [ -s "$OUTPUT_DIR/temp_filtered.txt" ]; then
        uro < "$OUTPUT_DIR/temp_filtered.txt" | sort -u > "$OUTPUT_DIR/all_urls.txt" 2>/dev/null
    elif [ -s "$OUTPUT_DIR/temp_filtered.txt" ]; then
        # Custom fast deduplication preserving parameter structure
        sort -u "$OUTPUT_DIR/temp_filtered.txt" | \
            awk '!seen[substr($0, 1, index($0, "?") ? index($0, "?") : length($0))]++' > "$OUTPUT_DIR/all_urls.txt" 2>/dev/null
    else
        # Fallback for any remaining URLs
        sort -u "$temp_file" 2>/dev/null | head -10000 > "$OUTPUT_DIR/all_urls.txt" || touch "$OUTPUT_DIR/all_urls.txt"
    fi
    
    # Clean up intermediate file
    rm -f "$OUTPUT_DIR/temp_filtered.txt"
    
    # Clean up temporary files
    rm -rf "$temp_dir" "$temp_file"
    
    local url_count=$(wc -l < "$OUTPUT_DIR/all_urls.txt" 2>/dev/null || echo "0")
    print_success "Gathered $url_count unique URLs in parallel"
    
    # Show sample URLs if verbose mode
    if [ "$url_count" -gt 0 ] && [ "$url_count" -lt 10 ]; then
        print_status "Sample URLs found:"
        cat "$OUTPUT_DIR/all_urls.txt" | head -5 | sed 's/^/  - /'
    elif [ "$url_count" -gt 0 ]; then
        print_status "Sample URLs found:"
        cat "$OUTPUT_DIR/all_urls.txt" | head -3 | sed 's/^/  - /'
        echo "  ... and $((url_count - 3)) more URLs"
    fi
}

# Function to safely execute grep with error handling
safe_grep() {
    local pattern="$1"
    local file="$2"
    local output_file="$3"
    
    # Validate inputs
    if [ -z "$pattern" ] || [ ! -f "$file" ] || [ -z "$output_file" ]; then
        print_error "Invalid parameters for safe_grep"
        return 1
    fi
    
    # Validate file is readable
    if [ ! -r "$file" ]; then
        print_error "Cannot read file: $file"
        return 1
    fi
    
    # Validate pattern before use with smart fallbacks
    if ! validate_pattern "$pattern"; then
        print_warning "Using fallback pattern for $filter_type"
        case "$filter_type" in
            "xss") pattern="[?&](q|search|input)=" ;;
            "openredirect") pattern="[?&](url|redirect)=" ;;
            "lfi") pattern="[?&](file|path|page)=" ;;
            "sqli") pattern="[?&](id|user|login)=" ;;
            "ssrf") pattern="[?&](url|uri|host)=" ;;
            "rce") pattern="[?&](cmd|exec)=" ;;
            "xxe") pattern="[?&](xml|api)=" ;;
            *) pattern="[?&][a-zA-Z]+=" ;;
        esac
    fi
    
    # Create output directory if needed
    mkdir -p "$(dirname "$output_file")"
    
    # Use grep with proper error handling, timeout, and resource limits
    {
        if command -v timeout >/dev/null 2>&1; then
            timeout 30 grep -iE "$pattern" "$file" 2>/dev/null | sed 's/=.*/=/' | sort -u > "$output_file"
        else
            # Fallback without timeout
            grep -iE "$pattern" "$file" 2>/dev/null | sed 's/=.*/=/' | sort -u > "$output_file"
        fi
    } || {
        # Create empty file on failure to prevent downstream errors
        touch "$output_file"
        print_warning "Pattern matching failed for $(basename "$output_file")"
        return 1
    }
    
    return 0
}

# Function to run parallel filtering jobs with enhanced error handling
run_parallel_filter() {
    local urls_file="$1"
    local filter_type="$2"
    local pattern="$3"
    local output_file="$OUTPUT_DIR/${filter_type}_endpoints.txt"
    
    # Validate inputs
    if [ ! -f "$urls_file" ] || [ -z "$filter_type" ] || [ -z "$pattern" ]; then
        print_error "Invalid parameters for filtering $filter_type"
        return 1
    fi
    
    print_status "Filtering URLs for potential $filter_type endpoints..."
    
    # Initialize output file
    touch "$output_file"
    
    # Try gf first if available and filter type matches
    if command_exists "gf" && [[ "$filter_type" != "rce" && "$filter_type" != "xxe" ]]; then
        local gf_pattern="$filter_type"
        case "$filter_type" in
            "openredirect") gf_pattern="redirect" ;;
            "lfi") gf_pattern="lfi" ;;
            "sqli") gf_pattern="sqli" ;;
            "ssrf") gf_pattern="ssrf" ;;
            "xss") gf_pattern="xss" ;;
        esac
        
        # Try gf with timeout and error handling
        if command -v timeout >/dev/null 2>&1; then
            if timeout 90 bash -c "cat '$urls_file' | gf '$gf_pattern' 2>/dev/null | sed 's/=.*/=/' | sort -u > '$output_file'" 2>/dev/null; then
                local count=$(wc -l < "$output_file" 2>/dev/null || echo "0")
                if [ "$count" -gt 0 ]; then
                    return 0
                fi
            fi
        fi
    fi
    
    # Fallback to safe_grep with enhanced error handling
    if safe_grep "$pattern" "$urls_file" "$output_file"; then
        return 0
    else
        print_warning "Fallback pattern matching failed for $filter_type, trying basic pattern"
        # Last resort: use keyword-based matching
        case "$filter_type" in
            "xss") 
                grep -iE "(search|query|input|message|comment)" "$urls_file" 2>/dev/null | grep -E '[?&]' | head -50 > "$output_file" || touch "$output_file"
                ;;
            "openredirect")
                grep -iE "(redirect|url|return|next)" "$urls_file" 2>/dev/null | grep -E '[?&]' | head -50 > "$output_file" || touch "$output_file"
                ;;
            "lfi")
                grep -iE "(file|path|page|include)" "$urls_file" 2>/dev/null | grep -E '[?&]' | head -50 > "$output_file" || touch "$output_file"
                ;;
            "sqli")
                grep -iE "(id|user|login|search|view)" "$urls_file" 2>/dev/null | grep -E '[?&]' | head -50 > "$output_file" || touch "$output_file"
                ;;
            "ssrf")
                grep -iE "(url|uri|host|domain|ping)" "$urls_file" 2>/dev/null | grep -E '[?&]' | head -50 > "$output_file" || touch "$output_file"
                ;;
            "rce")
                grep -iE "(cmd|exec|system|shell|ping)" "$urls_file" 2>/dev/null | grep -E '[?&]' | head -50 > "$output_file" || touch "$output_file"
                ;;
            "xxe")
                grep -iE "(xml|api|upload|import)" "$urls_file" 2>/dev/null | grep -E '[?&]' | head -50 > "$output_file" || touch "$output_file"
                ;;
            *)
                touch "$output_file"
                ;;
        esac
        print_warning "Used keyword fallback for $filter_type filtering"
        return 1
    fi
}

# Function to filter URLs for vulnerabilities with parallel processing
filter_vulnerabilities() {
    local urls_file="$OUTPUT_DIR/all_urls.txt"
    
    if [ ! -f "$urls_file" ] || [ ! -s "$urls_file" ]; then
        print_error "No URLs found to filter"
        return 1
    fi
    
    print_progress "Filtering URLs for different vulnerability types (parallel processing)"
    
    # Pre-process URLs for faster filtering with optimized deduplication
    local filtered_urls="$OUTPUT_DIR/filtered_urls.txt"
    
    # Only process URLs with parameters for vulnerability testing
    print_status "Pre-filtering URLs with parameters..."
    
    # Fast parameter extraction and deduplication
    if [ -s "$urls_file" ]; then
        # Extract only URLs with parameters, remove duplicates by base URL + param names
        grep -E '[?&][a-zA-Z0-9_-]+=' "$urls_file" 2>/dev/null | \
            head -50000 | \
            awk -F'[?&]' '{
                url_base = $1; params = ""
                for(i=2; i<=NF; i++) {
                    split($i, param_pair, "=")
                    if(param_pair[1] != "") params = params param_pair[1] "="
                }
                key = url_base "?" params
                if(!seen[key]++) print $0
            }' > "$filtered_urls" 2>/dev/null || touch "$filtered_urls"
    else
        touch "$filtered_urls"
    fi
    
    # If no parameters found, copy a sample of all URLs
    if [ ! -s "$filtered_urls" ] && [ -s "$urls_file" ]; then
        print_warning "No parameterized URLs found, using sample of all URLs"
        head -1000 "$urls_file" > "$filtered_urls"
    fi
    
    # Enhanced vulnerability filtering with optimized patterns
    declare -A vuln_patterns=(
        ["xss"]="(\\?|&)(q|query|search|keyword|s|p|input|text|msg|message|comment|content|data|term|value|name|title|description|body|html|script)="
        ["openredirect"]="(\\?|&)(url|redirect|return|next|continue|r|redir|goto|location|target|dest|destination|forward|link|href|src|path|uri)="
        ["lfi"]="(\\?|&)(file|path|page|include|dir|folder|template|document|load|read|view|show|display|get|fetch|open|cat|download|upload)="
        ["sqli"]="(\\?|&)(id|user|admin|login|page|cat|category|edit|delete|view|select|report|search|filter|sort|order|limit|offset|count|group|where|having|union)="
        ["ssrf"]="(\\?|&)(url|uri|path|continue|window|next|data|reference|site|html|val|validate|domain|callback|return|page|feed|host|port|to|out|view|dir|show|navigation|open|fetch|proxy|redirect|ping|connect|request|get|post)="
        ["rce"]="(\\?|&)(cmd|command|exec|execute|ping|system|shell|bash|sh|powershell|ps|run|call|invoke|eval|function|method|action|do|perform|launch)="
        ["xxe"]="(\\?|&)(xml|feed|soap|rest|api|upload|import|export|parse|process|load|file|document|content|data|input|source|stream|reader)="
    )
    
    # Special handling for XSS with Gxss and kxss
    if command_exists "Gxss" && command_exists "kxss"; then
        print_status "Filtering URLs for potential XSS endpoints (using Gxss+kxss)..."
        if timeout 120 bash -c "cat '$filtered_urls' | Gxss 2>/dev/null | kxss 2>/dev/null | grep -oP '^URL: \\K\\S+' 2>/dev/null | sed 's/=.*/=/' | sort -u > '$OUTPUT_DIR/xss_endpoints.txt'"; then
            : # Success
        else
            run_parallel_filter "$filtered_urls" "xss" "${vuln_patterns[xss]}" &
        fi
    else
        run_parallel_filter "$filtered_urls" "xss" "${vuln_patterns[xss]}" &
    fi
    
    # Run other filters in parallel with optimized patterns
    for vuln_type in openredirect lfi sqli ssrf rce xxe; do
        run_parallel_filter "$filtered_urls" "$vuln_type" "${vuln_patterns[$vuln_type]}" &
    done
    
    # Wait for all background jobs to complete with progress indication
    print_status "Waiting for parallel filtering to complete..."
    local job_count=$(jobs -r | wc -l)
    local wait_time=0
    local max_wait=300  # 5 minutes max wait
    
    while [ $(jobs -r | wc -l) -gt 0 ] && [ $wait_time -lt $max_wait ]; do
        local current_jobs=$(jobs -r | wc -l)
        echo -ne "\rFiltering in progress... $current_jobs jobs remaining (${wait_time}s)"
        sleep 2
        wait_time=$((wait_time + 2))
    done
    echo
    
    # Kill any remaining jobs if they exceed timeout
    if [ $(jobs -r | wc -l) -gt 0 ]; then
        print_warning "Some filtering jobs exceeded timeout, terminating..."
        jobs -p | xargs -r kill 2>/dev/null
        sleep 2
        jobs -p | xargs -r kill -9 2>/dev/null
    fi
    
    wait 2>/dev/null || true
    
    # Clean up temporary file
    rm -f "$filtered_urls"
    
    # Report results with enhanced statistics
    print_status "Vulnerability filtering summary:"
    local total_found=0
    
    for vuln_type in xss openredirect lfi sqli ssrf rce xxe; do
        local file="$OUTPUT_DIR/${vuln_type}_endpoints.txt"
        if [ -f "$file" ]; then
            local count=$(wc -l < "$file" 2>/dev/null || echo "0")
            if [ "$count" -gt 0 ]; then
                print_success "Found $count potential $vuln_type endpoints"
                total_found=$((total_found + count))
                
                # Show a sample if count is reasonable
                if [ "$count" -le 5 ] && [ "$count" -gt 0 ]; then
                    echo "  Sample endpoints:"
                    head -"$count" "$file" | sed 's/^/    - /'
                elif [ "$count" -gt 5 ]; then
                    echo "  Sample endpoints:"
                    head -3 "$file" | sed 's/^/    - /'
                    echo "    ... and $((count - 3)) more"
                fi
            else
                print_status "Found $count potential $vuln_type endpoints"
            fi
        fi
    done
    
    echo
    if [ "$total_found" -gt 0 ]; then
        print_success "Total potential vulnerable endpoints: $total_found"
    else
        print_warning "No potential vulnerable endpoints found - this could indicate:"
        echo "  - The target has good security practices"
        echo "  - Limited URL discovery"
        echo "  - URLs require authentication"
        echo "  - Consider manual testing of key endpoints"
    fi
}

# Function to generate summary report
generate_report() {
    local report_file="$OUTPUT_DIR/vulnerability_report.txt"
    local html_report="$OUTPUT_DIR/vulnerability_report.html"
    
    print_progress "Generating vulnerability assessment report"
    
    # Text report
    {
        echo "============================================"
        echo "Web Application Vulnerability Assessment Report"
        echo "Generated: $(date)"
        echo "Target: $1"
        echo "============================================"
        echo
        echo "SUMMARY:"
        echo "--------"
        
        for vuln_type in xss openredirect lfi sqli ssrf rce xxe; do
            local file="$OUTPUT_DIR/${vuln_type}_endpoints.txt"
            if [ -f "$file" ]; then
                local count=$(wc -l < "$file" 2>/dev/null || echo "0")
                echo "$(echo $vuln_type | tr '[:lower:]' '[:upper:]') endpoints: $count"
            fi
        done
        
        echo
        echo "DETAILED FINDINGS:"
        echo "------------------"
        
        for vuln_type in xss openredirect lfi sqli ssrf rce xxe; do
            local file="$OUTPUT_DIR/${vuln_type}_endpoints.txt"
            local vuln_name=""
            case $vuln_type in
                xss) vuln_name="Cross-Site Scripting (XSS)" ;;
                openredirect) vuln_name="Open Redirect" ;;
                lfi) vuln_name="Local File Inclusion (LFI)" ;;
                sqli) vuln_name="SQL Injection" ;;
                ssrf) vuln_name="Server-Side Request Forgery (SSRF)" ;;
                rce) vuln_name="Remote Code Execution (RCE)" ;;
                xxe) vuln_name="XML External Entity (XXE)" ;;
            esac
            
            if [ -f "$file" ] && [ -s "$file" ]; then
                echo
                echo "=== $vuln_name ==="
                head -20 "$file"
                local total=$(wc -l < "$file")
                if [ "$total" -gt 20 ]; then
                    echo "... and $((total - 20)) more endpoints"
                fi
            fi
        done
    } > "$report_file"
    
    # HTML report
    {
        echo "<!DOCTYPE html>"
        echo "<html><head><title>Vulnerability Assessment Report</title>"
        echo "<style>body{font-family:Arial,sans-serif;margin:20px;} .vuln{margin:20px 0;} .count{font-weight:bold;color:#d63384;} .endpoint{background:#f8f9fa;padding:5px;margin:2px 0;border-left:3px solid #0d6efd;}</style>"
        echo "</head><body>"
        echo "<h1>Web Application Vulnerability Assessment Report</h1>"
        echo "<p><strong>Target:</strong> $1</p>"
        echo "<p><strong>Generated:</strong> $(date)</p>"
        
        for vuln_type in xss openredirect lfi sqli ssrf rce xxe; do
            local file="$OUTPUT_DIR/${vuln_type}_endpoints.txt"
            local vuln_name=""
            case $vuln_type in
                xss) vuln_name="Cross-Site Scripting (XSS)" ;;
                openredirect) vuln_name="Open Redirect" ;;
                lfi) vuln_name="Local File Inclusion (LFI)" ;;
                sqli) vuln_name="SQL Injection" ;;
                ssrf) vuln_name="Server-Side Request Forgery (SSRF)" ;;
                rce) vuln_name="Remote Code Execution (RCE)" ;;
                xxe) vuln_name="XML External Entity (XXE)" ;;
            esac
            
            if [ -f "$file" ] && [ -s "$file" ]; then
                local count=$(wc -l < "$file")
                echo "<div class='vuln'>"
                echo "<h2>$vuln_name <span class='count'>($count endpoints)</span></h2>"
                head -10 "$file" | while IFS= read -r line; do
                    echo "<div class='endpoint'>$line</div>"
                done
                if [ "$count" -gt 10 ]; then
                    echo "<p><em>... and $((count - 10)) more endpoints</em></p>"
                fi
                echo "</div>"
            fi
        done
        
        echo "</body></html>"
    } > "$html_report"
    
    print_success "Reports generated: $report_file and $html_report"
}

# Function to run tests with enhanced feedback
run_tests() {
    print_status "Running comprehensive tests with progress tracking..."
    local test_count=0
    local passed_count=0
    
    local test_urls=(
        "https://example.com"
        "https://httpbin.org"
        "https://jsonplaceholder.typicode.com"
    )
    
    # Test URL validation functions
    print_status "[1/4] Testing URL validation functions..."
    for test_url in "${test_urls[@]}"; do
        test_count=$((test_count + 1))
        echo -ne "  Testing $test_url... "
        
        local normalized=$(normalize_url "$test_url")
        if validate_url "$normalized"; then
            echo -e "${GREEN}✓${NC}"
            passed_count=$((passed_count + 1))
        else
            echo -e "${RED}✗${NC}"
            print_error "URL validation test failed for $test_url"
        fi
    done
    
    # Test required tools availability
    print_status "[2/4] Testing tool availability..."
    local required_tools=("katana" "gf" "uro" "waybackurls" "gau" "subfinder" "httpx")
    local available_tools=0
    
    for tool in "${required_tools[@]}"; do
        test_count=$((test_count + 1))
        echo -ne "  Checking $tool... "
        
        if command_exists "$tool"; then
            echo -e "${GREEN}✓${NC}"
            available_tools=$((available_tools + 1))
            passed_count=$((passed_count + 1))
        else
            echo -e "${YELLOW}⚠${NC}"
        fi
    done
    
    # Test pattern validation
    print_status "[3/4] Testing regex pattern validation..."
    local test_patterns=(
        "(\\?|&)(q|search)="
        "[?&][a-zA-Z]+="
        "^https?://"
    )
    
    for pattern in "${test_patterns[@]}"; do
        test_count=$((test_count + 1))
        echo -ne "  Testing pattern '$pattern'... "
        
        if validate_pattern "$pattern"; then
            echo -e "${GREEN}✓${NC}"
            passed_count=$((passed_count + 1))
        else
            echo -e "${RED}✗${NC}"
        fi
    done
    
    # Test file operations
    print_status "[4/4] Testing file operations..."
    local test_dir="$OUTPUT_DIR/test"
    mkdir -p "$test_dir"
    
    # Test file creation
    test_count=$((test_count + 1))
    echo -ne "  Testing file creation... "
    if echo "test" > "$test_dir/test.txt" 2>/dev/null; then
        echo -e "${GREEN}✓${NC}"
        passed_count=$((passed_count + 1))
    else
        echo -e "${RED}✗${NC}"
    fi
    
    # Test file cleanup
    rm -rf "$test_dir" 2>/dev/null
    
    # Display results summary
    echo
    print_status "Test Results Summary:"
    echo "  Total tests: $test_count"
    echo -e "  Passed: ${GREEN}$passed_count${NC}"
    echo -e "  Failed: ${RED}$((test_count - passed_count))${NC}"
    echo -e "  Available tools: ${GREEN}$available_tools${NC}/${#required_tools[@]}"
    
    local success_rate=$((passed_count * 100 / test_count))
    if [ "$success_rate" -ge 80 ]; then
        print_success "Test suite passed with $success_rate% success rate"
        return 0
    else
        print_warning "Test suite completed with $success_rate% success rate"
        return 1
    fi
}

# Function to cleanup with enhanced error handling
cleanup() {
    print_status "Cleaning up temporary files and processes..."
    
    # Kill any remaining background processes
    jobs -p | xargs -r kill 2>/dev/null || true
    sleep 1
    jobs -p | xargs -r kill -9 2>/dev/null || true
    
    # Clean up temporary files and directories
    rm -rf "$OUTPUT_DIR/temp" "$OUTPUT_DIR/temp_urls.txt" "$OUTPUT_DIR/filtered_urls.txt" 2>/dev/null || true
    
    # Preserve scan results by default, only clean temp files
    # Set CLEANUP_ALL=true in environment to remove all files
    if [ "${CLEANUP_ALL:-false}" = "true" ]; then
        rm -f "$OUTPUT_DIR/all_urls.txt" 2>/dev/null || true
        print_status "All temporary and result files cleaned up"
    fi
}

# Function to display usage
usage() {
    echo -e "${WHITE}╔═══════════════════════════════════════════╗${NC}"
    echo -e "${WHITE}║     Web Application Vulnerability Scanner ║${NC}"
    echo -e "${WHITE}║              Enhanced Version             ║${NC}"
    echo -e "${WHITE}╚═══════════════════════════════════════════╝${NC}"
    echo
    echo -e "${CYAN}USAGE:${NC}"
    echo "  $(basename "$0") [OPTIONS]"
    echo
    echo -e "${YELLOW}OPTIONS:${NC}"
    echo -e "  ${GREEN}-u, --url URL${NC}        Target URL or domain to scan"
    echo -e "  ${GREEN}-t, --test${NC}           Run comprehensive tests only"
    echo -e "  ${GREEN}-i, --install${NC}        Install/check required tools only"
    echo -e "  ${GREEN}-h, --help${NC}           Show this help message"
    echo
    echo -e "${CYAN}EXAMPLES:${NC}"
    echo -e "  ${WHITE}Basic scan:${NC}"
    echo "    $(basename "$0") -u example.com"
    echo "    $(basename "$0") --url https://example.com"
    echo
    echo -e "  ${WHITE}Maintenance:${NC}"
    echo "    $(basename "$0") --test        # Run system tests"
    echo "    $(basename "$0") --install     # Install missing tools"
    echo
    echo -e "${PURPLE}FEATURES:${NC}"
    echo "  • Parallel URL discovery from multiple sources"
    echo "  • Advanced vulnerability pattern matching"
    echo "  • Support for 7 vulnerability types (XSS, SQLi, etc.)"
    echo "  • Enhanced error handling and progress tracking"
    echo "  • Detailed HTML and text reporting"
    echo
    echo -e "${YELLOW}OUTPUT:${NC}"
    echo "  Results are saved to: ./output/"
    echo "  • Individual endpoint files per vulnerability type"
    echo "  • Comprehensive HTML and text reports"
    echo "  • Raw URL collection for manual testing"
}

# Main function
main() {
    local website_input=""
    local test_mode=false
    local install_mode=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -u|--url)
                website_input="$2"
                shift 2
                ;;
            -t|--test)
                test_mode=true
                shift
                ;;
            -i|--install)
                install_mode=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
    
    # Set total steps for progress tracking
    if $test_mode; then
        TOTAL_STEPS=2
    elif $install_mode; then
        TOTAL_STEPS=1
    else
        TOTAL_STEPS=6
    fi
    
    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    
    # Handle different modes
    if $test_mode; then
        print_status "Running in test mode"
        run_tests
        return $?
    fi
    
    if $install_mode; then
        install_tools
        return $?
    fi
    
    # Enhanced interactive mode if no URL provided
    if [ -z "$website_input" ]; then
        echo -e "${CYAN}╔═══════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║     Web Application Vulnerability Scanner ║${NC}"
        echo -e "${CYAN}║              Enhanced Version             ║${NC}"
        echo -e "${CYAN}╚═══════════════════════════════════════════╝${NC}"
        echo
        echo -e "${WHITE}Features:${NC}"
        echo "  • Parallel URL discovery from multiple sources"
        echo "  • Advanced vulnerability pattern matching"
        echo "  • Enhanced error handling and timeouts"
        echo "  • Progress tracking and detailed reporting"
        echo
        echo -e "${YELLOW}Supported vulnerability types:${NC}"
        echo "  XSS, Open Redirect, LFI, SQLi, SSRF, RCE, XXE"
        echo
        
        while [ -z "$website_input" ]; do
            read -p "Enter the website URL or domain: " website_input
            
            if [ -z "$website_input" ]; then
                print_warning "URL is required. Please try again or use Ctrl+C to exit."
            fi
        done
    fi
    
    # Normalize and validate URL
    local website_url=$(normalize_url "$website_input")
    
    if ! validate_url "$website_url"; then
        exit 1
    fi
    
    print_success "Target URL: $website_url"
    
    # Set trap for cleanup with enhanced signal handling
    trap 'cleanup; exit 130' INT TERM
    trap 'cleanup' EXIT
    
    # Main execution flow
    print_progress "Installing/checking required tools"
    install_tools
    
    print_progress "Gathering URLs from multiple sources"
    gather_urls "$website_url"
    
    print_progress "Filtering URLs for vulnerabilities"
    filter_vulnerabilities
    
    print_progress "Generating comprehensive report"
    generate_report "$website_url"
    
    print_progress "Displaying results summary"
    echo
    echo -e "${WHITE}╔═══════════════════════════════════════════╗${NC}"
    echo -e "${WHITE}║          SCAN COMPLETED SUCCESSFULLY!     ║${NC}"
    echo -e "${WHITE}╚═══════════════════════════════════════════╝${NC}"
    echo
    
    # Display detailed results summary
    echo -e "${CYAN}📊 Results Summary:${NC}"
    local total_endpoints=0
    local file_count=0
    
    for file in "$OUTPUT_DIR"/*.txt "$OUTPUT_DIR"/*.html; do
        if [ -f "$file" ]; then
            file_count=$((file_count + 1))
            local basename_file=$(basename "$file")
            local size=$(du -h "$file" 2>/dev/null | cut -f1 || echo "0K")
            
            if [[ "$file" == *.txt ]] && [[ ! "$file" == *"report.txt" ]] && [[ ! "$file" == *"all_urls.txt" ]]; then
                local count=$(wc -l < "$file" 2>/dev/null || echo "0")
                total_endpoints=$((total_endpoints + count))
                
                if [ "$count" -gt 0 ]; then
                    echo -e "  ${GREEN}✓${NC} $basename_file: $count entries ($size)"
                else
                    echo -e "  ${YELLOW}•${NC} $basename_file: $count entries ($size)"
                fi
            else
                echo -e "  ${BLUE}📄${NC} $basename_file ($size)"
            fi
        fi
    done
    
    echo
    echo -e "${WHITE}📈 Statistics:${NC}"
    echo -e "  Total potential endpoints found: ${GREEN}$total_endpoints${NC}"
    echo -e "  Output files generated: ${BLUE}$file_count${NC}"
    echo -e "  Scan target: ${CYAN}$website_url${NC}"
    echo -e "  Scan completed: ${PURPLE}$(date)${NC}"
    
    if [ "$total_endpoints" -gt 0 ]; then
        echo
        echo -e "${GREEN}🎯 Next steps:${NC}"
        echo "  1. Review the generated reports in: $OUTPUT_DIR/"
        echo "  2. Prioritize testing based on endpoint counts"
        echo "  3. Use tools like Burp Suite or OWASP ZAP for testing"
        echo "  4. Consider manual testing for complex scenarios"
    fi
    
    print_success "Vulnerability assessment completed for $website_url"
}

# Execute main function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi

# ABOUTME: Complete automation guide for LOXS suite with filter.sh integration
# ABOUTME: Documents the automated workflow from reconnaissance through vulnerability assessment

# 🚀 Enhanced LOXS Automation Suite

## 📋 **Available Scripts & Their Purpose**

# Depracated
### 🔧 **Core Integration Scripts**

#| Script | Purpose | Usage |
#|--------|---------|-------|
#| `automate_all.py` | **Master automation** - Complete workflow | `./automate_all.py -d domain.com` |
#| `loxs_integration.py` | **Data processor** - filter.sh → loxs.py bridge | `./loxs_integration.py -d domain_output/` |
#| `loxs_wrapper.py` | **LOXS automator** - Batch vulnerability scanning | `./loxs_wrapper.py -f urls.txt` |
#| `orchestrator.py` | **Advanced orchestrator** - Full-featured pipeline | `./orchestrator.py -d domain.com` |

### 🛡️ **Enhanced Security Tools**

| Script | Purpose | Integration |
|--------|---------|-------------|
| `filter.sh` | **Enhanced reconnaissance** - Modern tools (Katana, URLfinder) | ✅ Automated |
| `loxs.py` | **Original vulnerability scanner** - Interactive mode | ✅ Wrapper integration |
| `hunter.py` | **IP analysis** - CVE & port reconnaissance | ✅ JSON output |

## 🔄 **Automated Workflow Steps**

```
1. 🔍 RECONNAISSANCE (filter.sh)
   ├── Domain enumeration (Amass)
   ├── Live host detection (HTTPX)
   ├── URL discovery (URLfinder + Katana + GAU)
   ├── Vulnerability scanning (Nuclei)
   └── Pattern matching (GF)

2. 🎯 VULNERABILITY SCANNING (loxs.py)
   ├── URL extraction & sampling (head/tail)
   ├── Batch processing (50 URLs/batch)
   ├── Multi-type scanning (LFI, XSS, SQLi, OR)
   └── Results aggregation

3. 🕵️ IP ANALYSIS (hunter.py)
   ├── IP extraction & sampling
   ├── CVE analysis (Shodan DB)
   ├── Port enumeration
   └── Risk assessment

4. 📊 REPORTING
   ├── Comprehensive HTML reports
   ├── JSON data export
   ├── Final summary report
   └── Next steps recommendations
```

## 💻 **Usage Examples**

### **Basic Automated Scan**
```bash
# Complete automation with all default settings
./automate_all.py -d example.com

# Output will be in: scan_results/example.com/
```

### **Custom Configuration**

### **Manual Integration Steps**
```bash
# Step 1: Run reconnaissance
./filter.sh -d example.com -o results --verbose

#  Analyze IPs
./hunter.py -f results/example.com/ip-addresses-example.com.txt --json-output results.json
```

## 📁 **Output Structure**

```
scan_results/
└── target.com/
    ├── domains-target.com.txt           # All discovered domains
    ├── livedomains-target.com.txt        # Live domains (HTTPX)
    ├── paths-target.com.txt              # All discovered URLs
    ├── ip-addresses-target.com.txt       # IP addresses
    ├── nuclei-target.com.jsonl          # Nuclei findings (JSON)
    ├── httpx-target.com.json            # HTTPX results (JSON)
    ├── check-manually/                   # GF pattern results
    │   ├── sql-injection.txt
    │   ├── cross-site-scripting.txt
    │   ├── local-file-inclusion.txt
    │   └── open-redirect.txt
    ├── loxs_urls_target.com.txt         # Processed URLs for LOXS
    ├── hunter_results_target.com.json   # IP analysis results
    └── FINAL_REPORT_target.com_TIMESTAMP.txt # Complete report
```

## ⚙️ **Configuration Options**

### **Reconnaissance Options (filter.sh)**
```bash
--quick         # Quick scan mode (reduced depth)
--passive-only  # Passive techniques only
--verbose       # Detailed output
--overwrite     # Force overwrite existing results
```

### **Vulnerability Scanning Options**
```bash
--max-urls 1000     # Maximum URLs to process
--scan-types 1 2 3  # Scan types: 1=LFI, 2=OR, 3=SQLi, 4=XSS, 5=CRLF
--batch-size 50     # URLs per batch
```

### **IP Analysis Options**
```bash
--threads 10        # Concurrent threads
--timeout 30        # Request timeout
--json-output       # JSON output file
--html-output       # HTML report file
```

## 🔍 **Efficient File Processing**

The automation uses intelligent sampling for large files:

### **URL Sampling Strategy**
```bash
# For files > 1000 lines:
# - 40% from head (most recent/important)
# - 40% from tail (comprehensive coverage)
# - 20% from middle (random sampling)

head -n 400 urls.txt          # Top URLs
tail -n 400 urls.txt          # Bottom URLs  
sed -n '500,700p' urls.txt    # Middle sample
```

### **IP Sampling Strategy**
```bash
# For files > 100 IPs:
# - First 50 IPs (primary targets)
# - Last 50 IPs (comprehensive coverage)

head -n 50 ips.txt
tail -n 50 ips.txt
```

## 🎛️ **Advanced Usage**



## 🛡️ **Security Best Practices**

### **Rate Limiting**
- **Reconnaissance**: Built-in rate limiting in tools
- **Vulnerability Scanning**: 50 URLs per batch with delays
- **IP Analysis**: Concurrent threading with timeouts

### **Data Handling**
- **Sampling**: Large files automatically sampled
- **Cleanup**: Temporary files removed after processing
- **Privacy**: No sensitive data stored in logs

### **Error Handling**
- **Graceful failures**: Continue on individual tool failures
- **Timeout protection**: All operations have timeouts
- **Resource management**: Automatic cleanup on interruption

## 📊 **Performance Metrics**

### **Expected Processing Times**
| Operation | Small Target | Medium Target | Large Target |
|-----------|-------------|---------------|-------------|
| Reconnaissance | 5-10 min | 15-30 min | 30-60 min |
| URL Processing | 1-2 min | 3-5 min | 5-10 min |
| Vuln Scanning | 10-20 min | 20-40 min | 40-80 min |
| IP Analysis | 2-5 min | 5-10 min | 10-20 min |
| **Total** | **18-37 min** | **43-85 min** | **85-170 min** |

### **Resource Usage**
- **CPU**: Moderate (multi-threading optimized)
- **Memory**: Low (streaming file processing)
- **Network**: Respectful (rate-limited requests)
- **Disk**: Efficient (compressed outputs, cleanup)

## 🔧 **Troubleshooting**

### **Common Issues**

#### **1. Dependencies Missing**
```bash
# Fix: Run setup script
./setup.sh -t /opt

# Or install individually
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest
```

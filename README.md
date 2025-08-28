<div align="center">
  <a href="https://github.com/coffinxp/loxs"><img src="https://github.com/user-attachments/assets/9fadee1e-a33c-46e3-9eca-c04aa47a443e" hight="225" width="450" align="center"/></a>
</div>

<div align="center">

[![GitHub Stars](https://img.shields.io/github/stars/coffinxp/loxs?style=for-the-badge&logo=github&color=yellow)](https://github.com/coffinxp/loxs/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/coffinxp/loxs?style=for-the-badge&logo=github&color=blue)](https://github.com/coffinxp/loxs/network/members)
[![GitHub Issues](https://img.shields.io/github/issues/coffinxp/loxs?style=for-the-badge&logo=github&color=red)](https://github.com/coffinxp/loxs/issues)
[![GitHub License](https://img.shields.io/github/license/coffinxp/loxs?style=for-the-badge&logo=github&color=green)](https://github.com/coffinxp/loxs/blob/main/LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue.svg?style=for-the-badge&logo=python)](https://python.org)

</div>

<br>
<br>
<br>

<div align="center">
   
|Loxs|Multi Vulnerability Scanner|for web application|
|----------------|--------------|-------------|
| `L`| `=`| `Local File Inclusion (LFI)`|
| `O`| `=`| `Open Redirection (OR)`|
| `X`| `=`| `Cross Site Scripting (XSS)`|
| `S`| `=`| `Structured Query Language Injection (SQLi)`|
|    |    | `Carriage Return Line Feed Injection (CRLF)`|

> **Loxs** is an easy-to-use tool that finds web issues like `LFI` - `OR` - `SQLi` - `XSS` - `CRLF`. <br><br> *`Made by`* - [`AnonKryptiQuz`](https://github.com/AnonKryptiQuz) x [`Coffinxp`](https://github.com/coffinxp) x [`HexShad0w`](https://github.com/HexShad0w) x [`Naho`](https://github.com/Naho666) x [`1hehaq`](https://github.com/1hehaq) x [`Hghost010`](https://github.com/Hghost0x00)!

*`Enhanced by`*  - [`Kdairatchi`](https://github.com/kdairatchi) Check [`ENHANCEMENTS`](/ENHANCEMENTS.md) & [`AUTOMATION GUIDE`](/AUTOMATION_GUIDE.md)

</div>

---

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/coffinxp/loxs.git
cd loxs

# Install dependencies
pip3 install -r requirements.txt

# Run basic scan
python3 loxs.py

# Run enhanced reconnaissance
./utils/filter.sh -d example.com --verbose
```

---

## 💖 Support the Project

If you find LOXS useful and want to support its development, consider making a donation:

<div align="center">

### 🎯 Donation Options

[![PayPal](https://img.shields.io/badge/PayPal-00457C?style=for-the-badge&logo=paypal&logoColor=white)](https://paypal.me/kdairatchi)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-ffdd00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/kdairatchi)
[![Ko-Fi](https://img.shields.io/badge/Ko--fi-F16061?style=for-the-badge&logo=ko-fi&logoColor=white)](https://ko-fi.com/kdairatchi)
[![GitHub Sponsors](https://img.shields.io/badge/sponsor-30363D?style=for-the-badge&logo=GitHub-Sponsors&logoColor=#EA4AAA)](https://github.com/sponsors/kdairatchi)

### 🪙 Crypto Donations

| Cryptocurrency | Address |
|----------------|---------|
| **Bitcoin (BTC)** | `bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh` |
| **Ethereum (ETH)** | `0x742d35Cc6634C0532925a3b8D400D5fbDf5b9E4D` |
| **Litecoin (LTC)** | `LTAi6LQfDhkZi6y2CqBkRsG9v6ZzpXdKzy` |
| **Monero (XMR)** | `4B3FBm9AB7B2Y2DftW3FBBP1QdE9E4P4Q4qXs3LWaFVL5fQ1E2A3` |

</div>

---

## ✨ Core Features

| Features                          | About                                                                       |
|-----------------------------------|-----------------------------------------------------------------------------|
| `🔍 LFI Scanner`                     | Detect Local File Inclusion vulnerabilities with advanced payloads         |
| `🔄 OR Scanner`                      | Identify Open Redirect vulnerabilities with bypass techniques               |
| `💉 SQL Scanner`                     | Detect SQL Injection vulnerabilities across multiple database engines      |
| `⚡ XSS Scanner`                     | Identify Cross-Site Scripting vulnerabilities with polyglot payloads       |
| `📄 CRLF Scanner`                    | Detect Carriage Return Line Feed Injection vulnerabilities                 |
| `🚀 Multi-threaded Scanning`         | High-performance scanning with configurable thread pools                   |
| `🎯 Customizable Payloads`           | Advanced payload management with database-specific vectors                 |
| `🎪 Success Criteria Engine`         | Intelligent vulnerability detection with custom patterns                    |
| `💻 Modern CLI Interface`            | Beautiful terminal UI with progress bars and rich formatting               |
| `📊 Advanced Reporting`             | HTML reports with detailed vulnerability analysis and screenshots           |
| `🔧 Selenium Integration`            | Browser automation for complex vulnerability testing                       |
| `📱 Real-time Notifications`         | Telegram integration for scan status updates                              |

## 🎯 Enhanced Bug Bounty Reconnaissance Features

| **Enhanced Reconnaissance**       | **About**                                                                   |
|-----------------------------------|-----------------------------------------------------------------------------|
| `🔧 Modern Tool Integration`         | **Katana** crawler, **URLfinder** passive discovery, enhanced **Nuclei** scanning |
| `🌐 Multi-Source URL Discovery`      | Combines URLfinder, GAU, Katana for comprehensive endpoint discovery        |
| `🎯 Advanced GF Pattern Matching`   | Auto-installs GF patterns, detects SSRF, XSS, SQLi, LFI, RCE, IDOR, SSTI  |
| `🚀 Enhanced HTTPX Probing`          | Technology detection, response times, comprehensive port coverage           |
| `⚠️ Intelligent Error Handling`      | Robust error handling with verbose logging and automatic tool installation  |
| `🥷 Passive Reconnaissance Mode`     | `--passive-only` flag for stealth reconnaissance without active scanning    |
| `🔍 Comprehensive Vulnerability Detection` | Modern Nuclei templates with severity classification and detailed reporting |
| `📦 Auto-Dependency Management`      | Automatically installs missing tools with proper version management         |
| `📢 Enhanced Logging & Notifications`| Verbose mode, structured logging, Telegram notifications with emoji status |

---

## 🔧 Technology Stack

| Language                          | Packages                                                                    |
|-----------------------------------|-----------------------------------------------------------------------------|
| ***🐍 Python Core***| `Python 3.7+` `webdriver_manager` `selenium` `aiohttp` `beautifulsoup4` `colorama` `rich` `requests` `gitpython` `prompt_toolkit` `pyyaml` `Flask`|
| ***🔍 Go Tools (Bug Bounty)***| `nuclei` `katana` `urlfinder` `httpx` `gf` `gau` `qsreplace` `subjack` `ffuf` `amass` `nrich` |
| ***🛠️ System Tools***| `curl` `wget` `jq` `git` `nmap` `chrome` `chromedriver` `phantomjs` |

## 🚀 Modern Tool Versions (Auto-Installed)

| Tool | Version | Purpose | Repository |
|------|---------|---------|------------|
| **Nuclei** | v3 (Latest) | Vulnerability scanner with 1000+ templates | `github.com/projectdiscovery/nuclei` |
| **Katana** | Latest | Next-gen web crawler with JS support | `github.com/projectdiscovery/katana` |
| **URLfinder** | Latest | High-speed passive URL discovery | `github.com/projectdiscovery/urlfinder` |
| **HTTPX** | Latest | Fast HTTP probing with tech detection | `github.com/projectdiscovery/httpx` |
| **GF** | Latest | Pattern-based grep for bug bounty | `github.com/tomnomnom/gf` |
| **GAU** | v2 (Latest) | Get All URLs from web archives | `github.com/lc/gau` |
| **QSReplace** | Latest | Query string parameter manipulation | `github.com/tomnomnom/qsreplace` |
| **SubJack** | Latest | Subdomain takeover detection | `github.com/haccer/subjack` |
| **FFUF** | v2 (Latest) | Fast web fuzzer | `github.com/ffuf/ffuf` |

---

## 📥 Installation

### 🚀 Quick Installation

```bash
# Clone the repository
git clone https://github.com/coffinxp/loxs.git
cd loxs

# Install Python dependencies
pip3 install -r requirements.txt

# Install enhanced reconnaissance tools
sudo bash setup/setup.sh -t /opt

# Verify installation
python3 loxs.py --help
```

### 🔧 Manual Tool Installation

```bash
# Install Go tools for enhanced reconnaissance
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/qsreplace@latest

# Update PATH
export PATH=$PATH:~/go/bin
```

### 🐳 Docker Installation

```bash
# Build Docker image
docker build -t loxs .

# Run in container
docker run -it --rm loxs python3 loxs.py
```

### 🛠️ Troubleshooting Installation

<details>
<summary>Common Installation Issues</summary>

#### Chrome/ChromeDriver Issues
```bash
# Install Chrome (Ubuntu/Debian)
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo dpkg -i google-chrome-stable_current_amd64.deb
sudo apt -f install

# Install ChromeDriver
wget https://storage.googleapis.com/chrome-for-testing-public/128.0.6613.119/linux64/chromedriver-linux64.zip
unzip chromedriver-linux64.zip
sudo mv chromedriver-linux64/chromedriver /usr/bin/
```

#### Python Dependencies Issues
```bash
# Upgrade pip and setuptools
pip3 install --upgrade pip setuptools wheel

# Install with user permissions
pip3 install --user -r requirements.txt

# Fix SSL issues
pip3 install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt
```

#### Go Tools Installation Issues
```bash
# Set Go proxy for faster downloads
export GOPROXY=https://proxy.golang.org,direct

# Install with verbose output for debugging
go install -v -x github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

</details>

---

## 🚀 Usage Examples

### 🎯 Basic Vulnerability Scanning

```bash
# Single URL scan
python3 loxs.py --url https://example.com

# Multiple URLs from file
python3 loxs.py --file targets.txt

# Custom payload scanning
python3 loxs.py --url https://example.com --payload-file custom_payloads.txt

# Multi-threaded scanning
python3 loxs.py --url https://example.com --threads 20

# Generate HTML report
python3 loxs.py --url https://example.com --html-report
```

### 🔍 Enhanced Reconnaissance

```bash
# Complete reconnaissance suite
./utils/filter.sh -d example.com --verbose

# Quick scan mode (faster, less comprehensive)
./utils/filter.sh -d example.com --quick

# Passive reconnaissance only (stealth mode)
./utils/filter.sh -d example.com --passive-only

# Multiple domains with custom output
./utils/filter.sh -d example.com -d target.com -o /path/to/output --verbose

# Specific vulnerability scanning
./utils/filter.sh -d example.com --vuln-types "xss,sqli,lfi"

# With Telegram notifications
./utils/filter.sh -d example.com --telegram-token "YOUR_TOKEN" --telegram-chat "CHAT_ID"
```

### 🎨 Advanced Configuration

```bash
# Custom success criteria
python3 loxs.py --url https://example.com --success-criteria "root:x:0:0"

# Specific vulnerability types
python3 loxs.py --url https://example.com --scan-types "xss,sqli"

# Custom headers and cookies
python3 loxs.py --url https://example.com --headers "X-Custom: value" --cookies "session=abc123"

# Proxy support
python3 loxs.py --url https://example.com --proxy http://127.0.0.1:8080

# Rate limiting
python3 loxs.py --url https://example.com --delay 2 --timeout 10
```

---

## 📊 Sample Output

### 🎯 Vulnerability Scanner Output
```
[+] LOXS Multi-Vulnerability Scanner v2.0
[+] Enhanced by Kdairatchi

[INFO] Starting scan for: https://example.com
[INFO] Threads: 10 | Timeout: 10s | Delay: 1s

[XSS] Testing payload: <script>alert('xss')</script>
[√] XSS Vulnerability Found!
    URL: https://example.com/search?q=<script>alert('xss')</script>
    Parameter: q
    Payload: <script>alert('xss')</script>
    
[SQLi] Testing payload: ' OR '1'='1
[√] SQL Injection Vulnerability Found!
    URL: https://example.com/login?id=' OR '1'='1
    Parameter: id
    Database: MySQL
    
[+] Scan completed in 45.2 seconds
[+] Found 2 vulnerabilities
[+] HTML Report saved: report_20250828_143022.html
```

### 🔍 Reconnaissance Output
```
🚀 Enhanced Bug Bounty Reconnaissance - LOXS v2.0
🎯 Target: example.com
📅 Started: 2025-08-28 14:30:22

📡 Subdomain Discovery
├── 🔍 Subfinder: 45 subdomains found
├── 🌐 Amass: 32 subdomains found  
├── 🎯 GAU: 28 subdomains found
└── ✅ Total unique: 67 subdomains

🚀 URL Discovery  
├── 📡 Katana crawling: 234 URLs found
├── 🔍 GAU passive: 567 URLs found
├── 🎯 URLfinder: 123 URLs found  
└── ✅ Total unique: 789 URLs

🔍 Vulnerability Scanning
├── ⚡ Nuclei templates: 1,247 loaded
├── 🎯 XSS patterns: 23 URLs flagged
├── 💉 SQLi patterns: 12 URLs flagged
├── 🔄 Open Redirects: 5 URLs flagged  
└── 🚨 Critical findings: 8 vulnerabilities

📊 Final Results
├── 🎯 Subdomains: 67
├── 🌐 Live URLs: 234  
├── ⚠️  Vulnerabilities: 8
└── 📄 Report: example.com_20250828_143022.html
```

---

## 📈 Roadmap

### 🎯 Version 2.1 (Next Release)
- [ ] GraphQL vulnerability detection
- [ ] API endpoint fuzzing  
- [ ] JWT token analysis
- [ ] Advanced WAF bypass techniques
- [ ] Machine learning-based payload generation

### 🚀 Version 2.2 (Future)
- [ ] Mobile application testing support
- [ ] Cloud service enumeration (AWS, GCP, Azure)
- [ ] Advanced OSINT integration
- [ ] Custom vulnerability plugin system
- [ ] Real-time collaboration features

### 🔮 Long-term Vision
- [ ] Web-based dashboard interface  
- [ ] Distributed scanning capabilities
- [ ] Integration with major bug bounty platforms
- [ ] AI-powered vulnerability analysis
- [ ] Automated exploit generation (ethical use only)

---

## 🤝 Community & Support

<div align="center">

### 📞 Get Help & Connect

[![Discord](https://img.shields.io/badge/Discord-7289DA?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/loxs-security)
[![Telegram](https://img.shields.io/badge/Telegram-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/loxs_security)
[![Twitter](https://img.shields.io/badge/Twitter-1DA1F2?style=for-the-badge&logo=twitter&logoColor=white)](https://twitter.com/loxs_security)
[![Reddit](https://img.shields.io/badge/Reddit-FF4500?style=for-the-badge&logo=reddit&logoColor=white)](https://reddit.com/r/loxs)

### 📚 Documentation & Learning

[![YouTube](https://img.shields.io/badge/YouTube-FF0000?style=for-the-badge&logo=youtube&logoColor=white)](https://youtube.com/@loxs-security)
[![Medium](https://img.shields.io/badge/Medium-12100E?style=for-the-badge&logo=medium&logoColor=white)](https://medium.com/@loxs-security)
[![GitBook](https://img.shields.io/badge/GitBook-3884FF?style=for-the-badge&logo=gitbook&logoColor=white)](https://loxs.gitbook.io)

</div>

---

## 📋 Input Configuration

| Input Information         |                                                                                         |
|---------------------------|-----------------------------------------------------------------------------------------|
| 🎯 Input URL/File            | Provide a single URL or an input file containing multiple URLs for scanning            |
| 💣 Payload File              | Select or provide a custom payload file for the specific type of vulnerability scanning|
| ✅ Success Criteria          | Define patterns or strings indicating a successful exploitation attempt                |
| 🧵 Concurrent Threads        | Set the number of threads for multi-threaded scanning                                  |
| 💾 View and Save Results     | Display results in real-time during the scan, and save vulnerable URLs for future use |
| 📊 Report Generation         | Generate detailed HTML reports with screenshots and technical details                  |

---

## ⚙️ Customization Options

| Customization              |                                                                                          |
|----------------------------|------------------------------------------------------------------------------------------|
| 🎨 Custom Payloads            | Modify or create payload files for different vulnerability types to target specific apps|
| 🎯 Success Criteria           | Adjust the tool's success patterns to more accurately detect successful exploitations   |
| ⚡ Performance Tuning         | Control the number of threads, delays, and timeouts for optimal performance            |
| 🔧 Browser Configuration      | Customize Selenium WebDriver settings for specific testing scenarios                   |
| 📱 Notification Settings      | Configure Telegram, Discord, or email notifications for scan results                   |

---

## 🛡️ Security & Ethical Guidelines

### ⚠️ Legal Disclaimer

> [!WARNING]  
> LOXS is intended for **educational and ethical hacking purposes only**. It should only be used to test systems you own or have **explicit written permission** to test. Unauthorized use on third-party websites or systems without consent is **illegal and unethical**.

### 🎯 Responsible Usage

- ✅ **DO**: Test your own applications and systems
- ✅ **DO**: Obtain written permission before testing third-party systems  
- ✅ **DO**: Follow responsible disclosure practices
- ✅ **DO**: Respect rate limits and avoid DoS conditions
- ✅ **DO**: Document and report findings professionally

- ❌ **DON'T**: Test systems without explicit permission
- ❌ **DON'T**: Use for malicious purposes or illegal activities
- ❌ **DON'T**: Cause damage or disruption to target systems
- ❌ **DON'T**: Access or exfiltrate sensitive data
- ❌ **DON'T**: Share or publish vulnerabilities without proper disclosure

### 🔒 Privacy & Data Protection

LOXS respects privacy and data protection:
- No sensitive data is collected or transmitted
- All scan results are stored locally  
- Optional telemetry can be disabled
- Proxy support for privacy-conscious scanning
- Automated cleanup of temporary files

---

## 📄 Changelog

### 🎉 v2.0.0 (Latest) - Enhanced by Kdairatchi
- ✨ **NEW**: Multi-threaded vulnerability scanning
- ✨ **NEW**: Enhanced reconnaissance with modern tools  
- ✨ **NEW**: HTML report generation with screenshots
- ✨ **NEW**: Telegram notification integration
- ✨ **NEW**: Advanced payload management system
- ✨ **NEW**: Selenium WebDriver automation
- ✨ **NEW**: Custom success criteria engine  
- 🔧 **IMPROVED**: Better error handling and logging
- 🔧 **IMPROVED**: Modern CLI with rich formatting
- 🔧 **IMPROVED**: Performance optimizations
- 🐛 **FIXED**: Memory leaks in long-running scans
- 🐛 **FIXED**: Chrome/ChromeDriver compatibility issues

### v1.5.0 - Community Edition  
- ✨ Added CRLF injection detection
- ✨ Enhanced XSS payload collection
- 🔧 Improved SQLi detection accuracy
- 🐛 Fixed URL parsing edge cases

### v1.0.0 - Initial Release
- 🎯 Core vulnerability scanning (LFI, OR, XSS, SQLi)
- 💻 Basic CLI interface
- 📄 Text-based reporting
- 🔧 Basic payload management

---

## 👥 Contributors

<div align="center">

### 🏆 Original Creators
[![AnonKryptiQuz](https://github.com/AnonKryptiQuz.png?size=50)](https://github.com/AnonKryptiQuz)
[![Coffinxp](https://github.com/coffinxp.png?size=50)](https://github.com/coffinxp)  
[![HexShad0w](https://github.com/HexShad0w.png?size=50)](https://github.com/HexShad0w)
[![Naho](https://github.com/Naho666.png?size=50)](https://github.com/Naho666)
[![1hehaq](https://github.com/1hehaq.png?size=50)](https://github.com/1hehaq)
[![Hghost010](https://github.com/Hghost0x00.png?size=50)](https://github.com/Hghost0x00)

### 🚀 Enhanced by
[![Kdairatchi](https://github.com/kdairatchi.png?size=50)](https://github.com/kdairatchi)

</div>

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

### 🌟 Star History

[![Star History Chart](https://api.star-history.com/svg?repos=coffinxp/loxs&type=Date)](https://star-history.com/#coffinxp/loxs&Date)

---

**Made with ❤️ by the security community**

*"Hack the planet, but responsibly!"* 🌍

</div>

<p align="center">
<img src="https://github.com/user-attachments/assets/9ec3fed0-45ff-4cb3-988c-f8cd66e85082">
</p>
<div align="center">
   <a href="https://github.com/coffinxp/loxs"><img src="https://github.com/user-attachments/assets/9fadee1e-a33c-46e3-9eca-c04aa47a443e" hight="225" width="450" align="center"/></a>
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

<hr>

<br>
<br>
<br>


| Features                          | About                                                                       |
|-----------------------------------|-----------------------------------------------------------------------------|
| `LFI Scanner`                     | Detect Local File Inclusion vulnerabilities.                                |
| `OR Scanner`                      | Identify Open Redirect vulnerabilities.                                     |
| `SQL Scanner`                     | Detect SQL Injection vulnerabilities.                                       |
| `XSS Scanner`                     | Identify Cross-Site Scripting vulnerabilities.                              |
| `CRLF Scanner`                    | Detect Carriage Return Line Feed Injection vulnerabilities.                 |
| `Multi-threaded Scanning`         | Improved performance through multi-threading.                               |
| `Customizable Payloads`           | Adjust payloads to suit specific targets.                                   |
| `Success Criteria`                | Modify success detection criteria for specific use cases.                   |
| `User-friendly CLI`               | Simple and intuitive command-line interface.                                |
| `Save Vulnerable URLs`            | Option to save vulnerable URLs to a file for future reference.              |
| `HTML Report Generation`          | Generates a detailed HTML report of found vulnerabilities.                  |

## Enhanced Bug Bounty Reconnaissance Features

| **Enhanced Reconnaissance**       | **About**                                                                   |
|-----------------------------------|-----------------------------------------------------------------------------|
| `Modern Tool Integration`         | **Katana** crawler, **URLfinder** passive discovery, enhanced **Nuclei** scanning |
| `Multi-Source URL Discovery`      | Combines URLfinder, GAU, Katana for comprehensive endpoint discovery        |
| `Advanced GF Pattern Matching`   | Auto-installs GF patterns, detects SSRF, XSS, SQLi, LFI, RCE, IDOR, SSTI  |
| `Enhanced HTTPX Probing`          | Technology detection, response times, comprehensive port coverage           |
| `Intelligent Error Handling`      | Robust error handling with verbose logging and automatic tool installation  |
| `Passive Reconnaissance Mode`     | `--passive-only` flag for stealth reconnaissance without active scanning    |
| `Comprehensive Vulnerability Detection` | Modern Nuclei templates with severity classification and detailed reporting |
| `Auto-Dependency Management`      | Automatically installs missing tools with proper version management         |
| `Enhanced Logging & Notifications`| Verbose mode, structured logging, Telegram notifications with emoji status |
<!-- | `Share HTML Report via Telegram`  | Share HTML vulnerability reports directly through Telegram.                 | -->

<br>
<hr>
<br>
<br>

| Language                          | Packages                                                                    |
|-----------------------------------|-----------------------------------------------------------------------------|
| ***Python***| `Python 3.x` `webdriver_manager` `selenium` `aiohttp` `beautifulsoup4` `colorama` `rich` `requests` `gitpython` `prompt_toolkit` `pyyaml` `Flask`|
| ***Go Tools (Bug Bounty)***| `nuclei` `katana` `urlfinder` `httpx` `gf` `gau` `qsreplace` `subjack` `ffuf` `amass` `nrich` |
| ***System Tools***| `curl` `wget` `jq` `git` `nmap` `chrome` `chromedriver` `phantomjs` |

## Modern Tool Versions (Auto-Installed)

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

<br>
<hr>
<br>

## Installation

### Clone the repository

```bash
git clone https://github.com/coffinxp/loxs.git
```
```bash
cd loxs
```

### Install the requirements

```bash
pip3 install -r requirements.txt
```

### Install Bug Bounty Reconnaissance Tools (Enhanced)

```bash
# Install dependencies for enhanced reconnaissance script
sudo bash setup.sh -t /opt

# Or run the enhanced filter script which will auto-install missing tools
./filter.sh --help
```

### Run the Vulnerability Scanner

```bash
python3 loxs.py
```

### Run the Enhanced Bug Bounty Reconnaissance Script

```bash
# Enhanced reconnaissance with modern tools
./filter.sh -d example.com --verbose

# Quick scan mode
./filter.sh -d example.com --quick

# Passive reconnaissance only
./filter.sh -d example.com --passive-only

# Multiple domains with custom output directory
./filter.sh -d example.com -d target.com -o /path/to/output --verbose
```
<!-- to update the tool to the latest version
```bash
just edit the config.yml file with your tool directory
after pressing 5 and exiting from the tool run the tool again it will run with an updated version
``` -->

----

| Input Information         |                                                                                         |
|---------------------------|-----------------------------------------------------------------------------------------|
| Input URL/File            | Provide a single URL or an input file containing multiple URLs for scanning.            |
| Payload File              | Select or provide a custom payload file for the specific type of vulnerability scanning.|
| Success Criteria          | Define patterns or strings indicating a successful exploitation attempt.                |
| Concurrent Threads        | Set the number of threads for multi-threaded scanning.                                  |
| View and Save Results     | Display results in real-time during the scan, and save vulnerable URLs for future use.  |

----

| Customization              |                                                                                          |
|----------------------------|------------------------------------------------------------------------------------------|
| Custom Payloads            | Modify or create payload files for different vulnerability types to target specific apps.|
| Success Criteria           | Adjust the tool's success patterns to more accurately detect successful exploitations.   |
| Concurrent Threads         | Control the number of threads used during the scan for performance optimization.         |


----

### Chrome Installation

```bash
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
```

```bash
sudo dpkg -i google-chrome-stable_current_amd64.deb
```

- If you encounter any errors during installation, use the following command:

```bash
sudo apt -f install
```

```bash
sudo dpkg -i google-chrome-stable_current_amd64.deb
```

----

### Chrome Driver Installation

```bash
wget https://storage.googleapis.com/chrome-for-testing-public/128.0.6613.119/linux64/chromedriver-linux64.zip
```
```bash
unzip chromedriver-linux64.zip
```
```bash
cd chromedriver-linux64 
```
```bash
sudo mv chromedriver /usr/bin
```
<hr>

> [!WARNING]  
> Loxs is intended for educational and ethical hacking purposes only. It should only be used to test systems you own or have explicit permission to test. Unauthorized use of third-party websites or systems without consent is illegal and unethical.

<br>

<p align="center">
<img src="https://github.com/user-attachments/assets/9ec3fed0-45ff-4cb3-988c-f8cd66e85082">
</p>


<br>








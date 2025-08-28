#!/usr/bin/env python3
# ABOUTME: Enhanced LazyHunter - IP reconnaissance and vulnerability analysis with JSON output and orchestrator integration
# ABOUTME: Processes IP addresses from reconnaissance phase and provides detailed CVE and port analysis with structured reporting

import requests
import datetime
import argparse
import signal
import os
import time
import json
import logging
import asyncio
import aiohttp
import base64
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from webdriver_manager.chrome import ChromeDriverManager
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

try:
    import pyppeteer
    PUPPETEER_AVAILABLE = True
except ImportError:
    PUPPETEER_AVAILABLE = False

import random
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Enhanced logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ANSI color codes
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"
PURPLE = "\033[95m"
BOLD = "\033[1m"

# Enhanced banner
BANNER = f"{GREEN}{BOLD}"
BANNER += "╔══════════════════════════════════════════════════════════════════╗\n"
BANNER += "║                                                                  ║\n"
BANNER += "║                     🕵️ LazyHunter v2.0 🕵️                        ║\n"
BANNER += "║                                                                  ║\n"
BANNER += "║                   IP Reconnaissance & CVE Analysis               ║\n"
BANNER += "║                          @kdairatchi                             ║\n"
BANNER += "║                                                                  ║\n"
BANNER += "╚══════════════════════════════════════════════════════════════════╝\n"
BANNER += f"{RESET}"

# Stealth User Agents and Headers
STEALTH_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/121.0"
]

STEALTH_HEADERS = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Cache-Control': 'no-cache',
    'Pragma': 'no-cache',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
    'Upgrade-Insecure-Requests': '1',
    'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"'
}

@dataclass
class IPAnalysisResult:
    """Data structure for IP analysis results"""
    ip: str
    hostnames: List[str] = None
    ports: List[int] = None
    vulns: List[Dict] = None
    cpe: List[str] = None
    tags: List[str] = None
    last_update: str = ""
    scan_timestamp: str = ""
    high_risk_cves: int = 0
    critical_cves: int = 0
    medium_risk_cves: int = 0
    low_risk_cves: int = 0
    total_cves: int = 0
    screenshots: List[Dict] = None
    web_services: List[Dict] = None

def signal_handler(sig, frame):
    """Enhanced signal handler"""
    choice = input(f"\n{YELLOW}Do you want to quit? (y/n): {RESET}")
    if choice.lower() == 'y':
        print(f"{RED}Exiting Enhanced LazyHunter...{RESET}")
        exit(0)

signal.signal(signal.SIGINT, signal_handler)

class EnhancedLazyHunter:
    """Enhanced LazyHunter with orchestrator integration"""
    
    def __init__(self, rate_limit: int = 10, timeout: int = 30, capture_screenshots: bool = False):
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.capture_screenshots = capture_screenshots
        self.results: List[IPAnalysisResult] = []
        self.session = requests.Session()
        
        # Use stealth headers for requests
        stealth_ua = random.choice(STEALTH_USER_AGENTS)
        headers = STEALTH_HEADERS.copy()
        headers['User-Agent'] = stealth_ua
        self.session.headers.update(headers)
        
        # Screenshot engines
        self.screenshot_engines = []
        self.playwright_browser = None
        self.selenium_driver = None
        
        if capture_screenshots:
            self._init_screenshot_engines()
    
    def _init_screenshot_engines(self):
        """Initialize multiple screenshot engines with stealth features"""
        available_engines = []
        
        # Try Playwright first (best stealth capabilities)
        if PLAYWRIGHT_AVAILABLE:
            try:
                self.playwright_context = sync_playwright()
                self.playwright = self.playwright_context.start()
                self.playwright_browser = self.playwright.chromium.launch(
                    headless=True,
                    args=[
                        '--no-sandbox',
                        '--disable-dev-shm-usage',
                        '--disable-blink-features=AutomationControlled',
                        '--disable-features=VizDisplayCompositor',
                        '--disable-background-timer-throttling',
                        '--disable-backgrounding-occluded-windows',
                        '--disable-renderer-backgrounding'
                    ]
                )
                available_engines.append('playwright')
                logger.info("🎭 Playwright screenshot engine initialized")
            except Exception as e:
                logger.warning(f"Playwright initialization failed: {e}")
        
        # Try Selenium as backup
        if SELENIUM_AVAILABLE:
            try:
                chrome_options = Options()
                stealth_ua = random.choice(STEALTH_USER_AGENTS)
                chrome_options.add_argument('--headless')
                chrome_options.add_argument('--no-sandbox')
                chrome_options.add_argument('--disable-dev-shm-usage')
                chrome_options.add_argument('--disable-gpu')
                chrome_options.add_argument('--window-size=1920,1080')
                chrome_options.add_argument(f'--user-agent={stealth_ua}')
                chrome_options.add_argument('--disable-blink-features=AutomationControlled')
                chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
                chrome_options.add_experimental_option('useAutomationExtension', False)
                
                service = Service(ChromeDriverManager().install())
                self.selenium_driver = webdriver.Chrome(service=service, options=chrome_options)
                self.selenium_driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
                available_engines.append('selenium')
                logger.info("🔧 Selenium screenshot engine initialized")
            except Exception as e:
                logger.warning(f"Selenium initialization failed: {e}")
        
        # Try Puppeteer as final backup
        if PUPPETEER_AVAILABLE:
            available_engines.append('puppeteer')
            logger.info("🎪 Puppeteer available as backup engine")
        
        self.screenshot_engines = available_engines
        if not available_engines:
            logger.error("❌ No screenshot engines available. Install: pip install playwright selenium pyppeteer")
    
    def capture_screenshot(self, url: str, service_name: str = "web") -> Optional[str]:
        """Capture screenshot using multiple engines with retry logic"""
        if not self.screenshot_engines:
            return None
        
        for engine in self.screenshot_engines:
            try:
                screenshot = self._capture_with_engine(url, engine)
                if screenshot:
                    logger.info(f"📸 Screenshot captured with {engine}: {url}")
                    return screenshot
            except Exception as e:
                logger.debug(f"Screenshot failed with {engine} for {url}: {e}")
                continue
        
        logger.warning(f"All screenshot engines failed for {url}")
        return None
    
    def _capture_with_engine(self, url: str, engine: str) -> Optional[str]:
        """Capture screenshot with specific engine"""
        if engine == 'playwright' and self.playwright_browser:
            return self._capture_playwright(url)
        elif engine == 'selenium' and self.selenium_driver:
            return self._capture_selenium(url)
        elif engine == 'puppeteer':
            return self._capture_puppeteer(url)
        return None
    
    def _capture_playwright(self, url: str) -> Optional[str]:
        """Capture screenshot using Playwright with stealth"""
        try:
            context = self.playwright_browser.new_context(
                user_agent=random.choice(STEALTH_USER_AGENTS),
                viewport={'width': 1920, 'height': 1080},
                extra_http_headers=STEALTH_HEADERS
            )
            
            # Add stealth scripts
            context.add_init_script("""
                Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
                Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
                Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
                window.chrome = { runtime: {} };
            """)
            
            page = context.new_page()
            page.goto(url, wait_until='networkidle', timeout=15000)
            time.sleep(2)  # Additional wait
            
            screenshot_bytes = page.screenshot(type='png', full_page=False)
            screenshot_b64 = base64.b64encode(screenshot_bytes).decode()
            
            page.close()
            context.close()
            return screenshot_b64
            
        except Exception as e:
            logger.debug(f"Playwright screenshot failed: {e}")
            return None
    
    def _capture_selenium(self, url: str) -> Optional[str]:
        """Capture screenshot using Selenium with stealth"""
        try:
            self.selenium_driver.get(url)
            time.sleep(3)
            screenshot_b64 = self.selenium_driver.get_screenshot_as_base64()
            return screenshot_b64
        except Exception as e:
            logger.debug(f"Selenium screenshot failed: {e}")
            return None
    
    def _capture_puppeteer(self, url: str) -> Optional[str]:
        """Capture screenshot using Puppeteer with stealth"""
        try:
            async def _async_puppeteer_capture():
                browser = await pyppeteer.launch({
                    'headless': True,
                    'args': [
                        '--no-sandbox',
                        '--disable-setuid-sandbox',
                        '--disable-dev-shm-usage',
                        '--disable-blink-features=AutomationControlled'
                    ]
                })
                
                page = await browser.newPage()
                
                # Set stealth headers and user agent
                stealth_ua = random.choice(STEALTH_USER_AGENTS)
                await page.setUserAgent(stealth_ua)
                await page.setExtraHTTPHeaders(STEALTH_HEADERS)
                
                # Stealth scripts
                await page.evaluateOnNewDocument("""
                    Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
                    Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
                    window.chrome = { runtime: {} };
                """)
                
                await page.goto(url, {'waitUntil': 'networkidle0', 'timeout': 15000})
                await asyncio.sleep(2)
                
                screenshot_bytes = await page.screenshot({'type': 'png'})
                screenshot_b64 = base64.b64encode(screenshot_bytes).decode()
                
                await browser.close()
                return screenshot_b64
            
            # Run the async function synchronously
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(_async_puppeteer_capture())
            loop.close()
            return result
            
        except Exception as e:
            logger.debug(f"Puppeteer screenshot failed: {e}")
            return None
    
    def scan_web_services(self, ip: str, ports: List[int]) -> List[Dict]:
        """Scan for web services on common ports and capture screenshots"""
        web_services = []
        common_web_ports = [80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9000]
        
        if not ports:
            return web_services
        
        web_ports = [port for port in ports if port in common_web_ports]
        
        for port in web_ports:
            # Try HTTPS first, then HTTP
            protocols = ['https', 'http'] if port in [443, 8443] else ['http', 'https']
            
            for protocol in protocols:
                url = f"{protocol}://{ip}:{port}"
                try:
                    # Use random stealth headers for each request
                    headers = STEALTH_HEADERS.copy()
                    headers['User-Agent'] = random.choice(STEALTH_USER_AGENTS)
                    
                    response = self.session.get(url, timeout=10, verify=False, headers=headers)
                    if response.status_code < 400:
                        service_info = {
                            'url': url,
                            'protocol': protocol,
                            'port': port,
                            'status_code': response.status_code,
                            'title': self._extract_title(response.text),
                            'server': response.headers.get('Server', 'Unknown'),
                            'screenshot': None
                        }
                        
                        if self.capture_screenshots and self.driver:
                            service_info['screenshot'] = self.capture_screenshot(url)
                        
                        web_services.append(service_info)
                        break  # Found working protocol, move to next port
                except Exception:
                    continue
        
        return web_services
    
    def _extract_title(self, html_content: str) -> str:
        """Extract title from HTML content"""
        try:
            import re
            title_match = re.search(r'<title[^>]*>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
            if title_match:
                return title_match.group(1).strip()[:100]  # Limit title length
        except Exception:
            pass
        return "Unknown"
    
    def cleanup(self):
        """Cleanup screenshot engines"""
        try:
            if self.playwright_browser:
                self.playwright_browser.close()
            if hasattr(self, 'playwright'):
                self.playwright.stop()
            if hasattr(self, 'playwright_context'):
                self.playwright_context.__exit__(None, None, None)
            if self.selenium_driver:
                self.selenium_driver.quit()
        except Exception as e:
            logger.debug(f"Cleanup error: {e}")
        
    def get_severity_color(self, cvss_score: float) -> str:
        """Enhanced severity color coding"""
        if cvss_score is None or cvss_score == 0:
            return f"{GREEN}[INFO]{RESET}"
        elif cvss_score >= 9.0:
            return f"{RED}{BOLD}[CRITICAL]{RESET}"
        elif cvss_score >= 7.0:
            return f"{RED}[HIGH]{RESET}"
        elif cvss_score >= 4.0:
            return f"{YELLOW}[MEDIUM]{RESET}"
        else:
            return f"{GREEN}[LOW]{RESET}"
    
    def fetch_cve_details(self, cve_id: str) -> Dict:
        """Enhanced CVE details fetching with caching"""
        try:
            url = f"https://cvedb.shodan.io/cve/{cve_id}"
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            logger.debug(f"Error fetching CVE {cve_id}: {e}")
        return {}
    
    def analyze_single_ip(self, ip: str) -> Optional[IPAnalysisResult]:
        """Enhanced IP analysis with structured output"""
        logger.info(f"🔍 Analyzing IP: {ip}")
        
        try:
            url = f"https://internetdb.shodan.io/{ip}"
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                result = self._process_ip_data(ip, data)
                return result
            else:
                logger.warning(f"Failed to fetch data for {ip}: HTTP {response.status_code}")
                return None
                
        except requests.exceptions.Timeout:
            logger.error(f"Timeout analyzing {ip}")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error for {ip}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error analyzing {ip}: {e}")
            return None
    
    def _process_ip_data(self, ip: str, data: Dict) -> IPAnalysisResult:
        """Process IP data into structured result"""
        result = IPAnalysisResult(
            ip=ip,
            hostnames=data.get("hostnames", []),
            ports=data.get("ports", []),
            cpe=data.get("cpe", []),
            tags=data.get("tags", []),
            last_update=data.get("last_update", ""),
            scan_timestamp=datetime.datetime.now().isoformat()
        )
        
        # Process CVEs
        vulns = data.get("vulns", [])
        if vulns:
            cve_details = []
            severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            
            for cve_id in vulns:
                cve_info = self.fetch_cve_details(cve_id)
                if cve_info:
                    cvss_score = cve_info.get("cvss_v3") or cve_info.get("cvss", 0)
                    
                    # Count by severity
                    if cvss_score >= 9.0:
                        severity_counts['critical'] += 1
                    elif cvss_score >= 7.0:
                        severity_counts['high'] += 1
                    elif cvss_score >= 4.0:
                        severity_counts['medium'] += 1
                    else:
                        severity_counts['low'] += 1
                    
                    cve_details.append({
                        'id': self._sanitize_string(cve_id),
                        'cvss': cvss_score,
                        'summary': self._sanitize_string(cve_info.get('summary', ''))[:200],  # Truncate
                        'published': cve_info.get('published', ''),
                        'modified': cve_info.get('modified', '')
                    })
                    
                time.sleep(0.1)  # Rate limiting
            
            result.vulns = cve_details
            result.critical_cves = severity_counts['critical']
            result.high_risk_cves = severity_counts['high']
            result.medium_risk_cves = severity_counts['medium']
            result.low_risk_cves = severity_counts['low']
            result.total_cves = len(cve_details)
        
        # Scan for web services and capture screenshots
        if result.ports and self.capture_screenshots:
            result.web_services = self.scan_web_services(ip, result.ports)
        
        return result
    
    def _sanitize_string(self, text: str) -> str:
        """Sanitize strings to prevent XSS in HTML reports"""
        import html
        if isinstance(text, str):
            return html.escape(text)
        return str(text)
    
    def analyze_ips_from_file(self, file_path: str, max_workers: int = 10) -> List[IPAnalysisResult]:
        """Analyze multiple IPs from file with threading"""
        logger.info(f"📂 Loading IPs from: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                ips = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            logger.error(f"File not found: {file_path}")
            return []
        except Exception as e:
            logger.error(f"Error reading file: {e}")
            return []
        
        if not ips:
            logger.warning("No IPs found in file")
            return []
        
        logger.info(f"🚀 Starting analysis of {len(ips)} IP addresses")
        
        results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ip = {executor.submit(self.analyze_single_ip, ip): ip for ip in ips}
            
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        self._display_result(result)
                except Exception as e:
                    logger.error(f"Error processing {ip}: {e}")
        
        self.results.extend(results)
        return results
    
    def _display_result(self, result: IPAnalysisResult):
        """Display analysis result in enhanced format"""
        timestamp = f"{YELLOW}[{datetime.datetime.now().strftime('%H:%M:%S')}]{RESET}"
        ip_colored = f"{BLUE}[{result.ip}]{RESET}"
        
        # Display ports
        if result.ports:
            ports_colored = ', '.join(f"{GREEN}{port}{RESET}" for port in result.ports)
            print(f"{timestamp} {ip_colored} [PORTS: {ports_colored}]")
        
        # Display hostnames
        if result.hostnames:
            hostnames_colored = ', '.join(f"{GREEN}{host}{RESET}" for host in result.hostnames)
            print(f"{timestamp} {ip_colored} [HOSTNAMES: {hostnames_colored}]")
        
        # Display CVEs with enhanced info
        if result.vulns:
            print(f"{timestamp} {ip_colored} {RED}[CVE ANALYSIS]{RESET}")
            print(f"    📊 Critical: {RED}{result.critical_cves}{RESET}, High: {YELLOW}{result.high_risk_cves}{RESET}, "
                  f"Medium: {GREEN}{result.medium_risk_cves}{RESET}, Low: {CYAN}{result.low_risk_cves}{RESET}")
            
            # Display top 3 most critical CVEs
            sorted_cves = sorted(result.vulns, key=lambda x: x.get('cvss', 0), reverse=True)
            for cve in sorted_cves[:3]:
                severity = self.get_severity_color(cve.get('cvss', 0))
                print(f"    🎯 {GREEN}{cve['id']}{RESET} {severity} - {cve.get('summary', 'No description')[:80]}")
        
        print()  # Empty line for readability
    
    def generate_json_report(self, output_file: str = None) -> str:
        """Generate JSON report for orchestrator integration"""
        if output_file is None:
            output_file = f"hunter_analysis_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        report_data = {
            'scan_info': {
                'timestamp': datetime.datetime.now().isoformat(),
                'total_ips': len(self.results),
                'tool_version': '2.0',
                'total_cves_found': sum(r.total_cves for r in self.results),
                'critical_findings': sum(r.critical_cves for r in self.results),
                'high_risk_findings': sum(r.high_risk_cves for r in self.results)
            },
            'results': [asdict(result) for result in self.results]
        }
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"📊 JSON report generated: {output_file}")
            return output_file
            
        except Exception as e:
            logger.error(f"Error generating JSON report: {e}")
            return ""
    
    def generate_html_report(self, output_file: str = None, auto_open: bool = True) -> str:
        """Generate cyberpunk-styled HTML report with enhanced visualization"""
        if output_file is None:
            output_file = f"hunter_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        # Calculate statistics
        total_ips = len(self.results)
        total_cves = sum(r.total_cves for r in self.results)
        critical_cves = sum(r.critical_cves for r in self.results)
        high_cves = sum(r.high_risk_cves for r in self.results)
        medium_cves = sum(r.medium_risk_cves for r in self.results)
        low_cves = sum(r.low_risk_cves for r in self.results)
        
        # Generate HTML content with cyberpunk theme
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🕵️ LazyHunter - CyberSec Intelligence Report</title>
    <!-- Content Security Policy -->
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self';">
    <!-- Using CDN with integrity check for security -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" 
          rel="stylesheet" 
          integrity="sha512-Avb2QiuDEEvB4bZJYdft2mNjVShBftLdPG8FJ0V7irTLQ8Uo0qcPxh4Plq7G5tGm0rU+1SPhVotteLpBERwTkw==" 
          crossorigin="anonymous" 
          referrerpolicy="no-referrer">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Roboto+Mono:wght@300;400;700&display=swap');
        
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{ 
            font-family: 'Roboto Mono', monospace; 
            background: linear-gradient(135deg, #0a0a0a 0%, #1a1a1a 50%, #0a0a0a 100%);
            color: #00ff88;
            min-height: 100vh;
            overflow-x: hidden;
        }}
        
        .matrix-bg {{
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><defs><pattern id="grid" width="10" height="10" patternUnits="userSpaceOnUse"><path d="M 10 0 L 0 0 0 10" fill="none" stroke="%23003300" stroke-width="0.5" opacity="0.3"/></pattern></defs><rect width="100" height="100" fill="url(%23grid)"/></svg>');
            z-index: -1;
        }}
        
        .glitch {{ animation: glitch 2s infinite; }}
        @keyframes glitch {{
            0%, 100% {{ transform: translate(0); }}
            20% {{ transform: translate(-2px, 2px); }}
            40% {{ transform: translate(-2px, -2px); }}
            60% {{ transform: translate(2px, 2px); }}
            80% {{ transform: translate(2px, -2px); }}
        }}
        
        .container {{ 
            max-width: 1400px; margin: 0 auto; padding: 20px;
            background: rgba(0, 0, 0, 0.9); 
            border: 2px solid #00ff88; 
            border-radius: 15px;
            box-shadow: 0 0 50px rgba(0, 255, 136, 0.3), inset 0 0 50px rgba(0, 255, 136, 0.1);
            backdrop-filter: blur(10px);
        }}
        
        .header {{ 
            text-align: center; padding: 40px 20px;
            background: linear-gradient(45deg, #001122, #003344, #001122);
            border: 1px solid #00ff88;
            border-radius: 10px;
            margin-bottom: 30px;
            position: relative;
        }}
        
        .header::before {{
            content: ''; position: absolute; top: -2px; left: -2px; right: -2px; bottom: -2px;
            background: linear-gradient(45deg, #00ff88, #ff0080, #0088ff, #00ff88);
            border-radius: 12px; z-index: -1;
            animation: borderGlow 3s linear infinite;
        }}
        
        @keyframes borderGlow {{
            0%, 100% {{ opacity: 0.8; }}
            50% {{ opacity: 0.4; }}
        }}
        
        h1 {{ 
            font-family: 'Orbitron', monospace; 
            font-size: 3.5rem; 
            color: #00ff88;
            text-shadow: 0 0 20px #00ff88, 0 0 40px #00ff88;
            margin-bottom: 10px;
            letter-spacing: 3px;
        }}
        
        .subtitle {{ 
            color: #66ffaa; 
            font-size: 1.2rem;
            text-shadow: 0 0 10px #66ffaa;
        }}
        
        .timestamp {{ 
            color: #888; 
            font-size: 1rem; 
            margin-top: 15px;
            font-family: 'Roboto Mono', monospace;
        }}
        
        .stats {{ 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); 
            gap: 25px; 
            margin: 30px 0; 
        }}
        
        .stat-card {{ 
            background: linear-gradient(135deg, rgba(0, 255, 136, 0.1), rgba(0, 255, 136, 0.05));
            border: 2px solid #00ff88;
            border-radius: 15px;
            padding: 25px;
            text-align: center;
            position: relative;
            overflow: hidden;
            transition: all 0.3s ease;
        }}
        
        .stat-card:hover {{ 
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0, 255, 136, 0.4);
        }}
        
        .stat-card::before {{
            content: ''; position: absolute; top: 0; left: -100%; width: 100%; height: 100%;
            background: linear-gradient(90deg, transparent, rgba(0, 255, 136, 0.2), transparent);
            transition: left 0.5s;
        }}
        
        .stat-card:hover::before {{ left: 100%; }}
        
        .stat-value {{ 
            font-size: 3rem; 
            font-weight: 900; 
            font-family: 'Orbitron', monospace;
            text-shadow: 0 0 15px currentColor;
            margin-bottom: 10px;
        }}
        
        .stat-label {{ 
            font-size: 1rem;
            text-transform: uppercase;
            letter-spacing: 2px;
            opacity: 0.9;
        }}
        
        .critical {{ color: #ff3366; text-shadow: 0 0 15px #ff3366; }}
        .high {{ color: #ff8800; text-shadow: 0 0 15px #ff8800; }}
        .medium {{ color: #ffcc00; text-shadow: 0 0 15px #ffcc00; }}
        .low {{ color: #00ff88; text-shadow: 0 0 15px #00ff88; }}
        
        .content {{ padding: 0; }}
        
        .section-title {{ 
            font-family: 'Orbitron', monospace;
            font-size: 2.5rem;
            color: #00ff88;
            text-align: center;
            margin: 40px 0;
            text-shadow: 0 0 20px #00ff88;
        }}
        
        .ip-card {{ 
            background: linear-gradient(135deg, rgba(0, 50, 30, 0.8), rgba(0, 30, 20, 0.8));
            border: 2px solid #00ff88;
            border-radius: 15px;
            margin-bottom: 25px;
            overflow: hidden;
            transition: all 0.3s ease;
        }}
        
        .ip-card:hover {{ 
            border-color: #66ffaa;
            box-shadow: 0 0 30px rgba(0, 255, 136, 0.3);
        }}
        
        .ip-header {{ 
            background: linear-gradient(90deg, #002211, #003322);
            padding: 20px;
            border-bottom: 1px solid #00ff88;
        }}
        
        .ip-address {{ 
            font-family: 'Orbitron', monospace;
            font-size: 1.8rem;
            color: #00ff88;
            text-shadow: 0 0 10px #00ff88;
        }}
        
        .hostname {{ 
            color: #66ffaa;
            margin-top: 5px;
            font-size: 0.9rem;
        }}
        
        .ip-details {{ padding: 20px; }}
        
        .detail-section {{ 
            margin-bottom: 20px;
            padding: 15px;
            background: rgba(0, 255, 136, 0.05);
            border-radius: 10px;
            border-left: 4px solid #00ff88;
        }}
        
        .detail-title {{ 
            font-weight: bold;
            color: #66ffaa;
            margin-bottom: 10px;
            font-size: 1.1rem;
        }}
        
        .port-list {{ 
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }}
        
        .port-badge {{ 
            background: linear-gradient(45deg, #00ff88, #00cc66);
            color: #000;
            padding: 5px 12px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9rem;
            box-shadow: 0 2px 10px rgba(0, 255, 136, 0.3);
        }}
        
        .cve-summary {{ 
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin-bottom: 20px;
        }}
        
        .cve-count {{ 
            text-align: center;
            padding: 10px;
            border-radius: 10px;
            background: rgba(255, 255, 255, 0.05);
        }}
        
        .cve-list {{ 
            max-height: 400px;
            overflow-y: auto;
            scrollbar-width: thin;
            scrollbar-color: #00ff88 #222;
        }}
        
        .cve-item {{ 
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 10px;
            border-left: 4px solid;
            background: rgba(0, 0, 0, 0.3);
            transition: all 0.3s ease;
        }}
        
        .cve-item:hover {{ 
            transform: translateX(5px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
        }}
        
        .cve-critical {{ border-left-color: #ff3366; }}
        .cve-high {{ border-left-color: #ff8800; }}
        .cve-medium {{ border-left-color: #ffcc00; }}
        .cve-low {{ border-left-color: #00ff88; }}
        
        .cve-header {{ 
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }}
        
        .cve-id {{ 
            font-family: 'Orbitron', monospace;
            font-weight: bold;
            font-size: 1.1rem;
        }}
        
        .cvss-score {{ 
            background: rgba(255, 255, 255, 0.1);
            padding: 2px 8px;
            border-radius: 15px;
            font-size: 0.9rem;
        }}
        
        .cve-summary-text {{ 
            color: #ccc;
            line-height: 1.4;
            font-size: 0.95rem;
        }}
        
        .no-data {{ 
            text-align: center;
            color: #666;
            font-style: italic;
            padding: 20px;
        }}
        
        /* Scrollbar styling */
        ::-webkit-scrollbar {{ width: 8px; }}
        ::-webkit-scrollbar-track {{ background: #111; }}
        ::-webkit-scrollbar-thumb {{ background: #00ff88; border-radius: 4px; }}
        ::-webkit-scrollbar-thumb:hover {{ background: #66ffaa; }}
        
        /* Dashboard Controls */
        .controls-section {{
            background: rgba(0, 50, 30, 0.8);
            border: 2px solid #00ff88;
            border-radius: 15px;
            padding: 25px;
            margin: 30px 0;
        }}
        
        .search-container {{
            position: relative;
            margin-bottom: 20px;
        }}
        
        .search-input {{
            width: 100%;
            padding: 15px 50px 15px 20px;
            background: rgba(0, 0, 0, 0.8);
            border: 2px solid #00ff88;
            border-radius: 25px;
            color: #00ff88;
            font-family: 'Roboto Mono', monospace;
            font-size: 1rem;
        }}
        
        .search-input:focus {{
            outline: none;
            box-shadow: 0 0 20px rgba(0, 255, 136, 0.5);
        }}
        
        .clear-btn {{
            position: absolute;
            right: 10px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            color: #ff3366;
            cursor: pointer;
            padding: 10px;
        }}
        
        .filter-controls {{
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }}
        
        .filter-select {{
            padding: 10px 15px;
            background: rgba(0, 0, 0, 0.8);
            border: 2px solid #00ff88;
            border-radius: 20px;
            color: #00ff88;
            font-family: 'Roboto Mono', monospace;
        }}
        
        .view-toggle {{
            padding: 10px 20px;
            background: linear-gradient(45deg, #00ff88, #00cc66);
            border: none;
            border-radius: 20px;
            color: #000;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s ease;
        }}
        
        .view-toggle:hover {{
            transform: scale(1.05);
        }}
        
        .dashboard-stats {{
            display: flex;
            gap: 30px;
            margin: 20px 0;
            justify-content: center;
        }}
        
        .quick-stat {{
            text-align: center;
            padding: 15px 25px;
            background: rgba(0, 255, 136, 0.1);
            border: 1px solid #00ff88;
            border-radius: 10px;
        }}
        
        .stat-number {{
            display: block;
            font-size: 2rem;
            font-weight: bold;
            color: #00ff88;
            font-family: 'Orbitron', monospace;
        }}
        
        .stat-desc {{
            font-size: 0.9rem;
            color: #66ffaa;
            text-transform: uppercase;
        }}
        
        .results-grid {{
            display: grid;
            gap: 25px;
        }}
        
        .results-table {{
            display: none;
        }}
        
        .results-table table {{
            width: 100%;
            border-collapse: collapse;
            background: rgba(0, 0, 0, 0.8);
            border-radius: 10px;
            overflow: hidden;
        }}
        
        .results-table th, .results-table td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #00ff88;
        }}
        
        .results-table th {{
            background: rgba(0, 255, 136, 0.2);
            font-weight: bold;
        }}
        
        /* Screenshot Modal */
        .modal {{
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.9);
        }}
        
        .modal-content {{
            background: linear-gradient(135deg, rgba(0, 50, 30, 0.9), rgba(0, 30, 20, 0.9));
            margin: 2% auto;
            padding: 30px;
            border: 2px solid #00ff88;
            border-radius: 15px;
            width: 90%;
            max-width: 1200px;
            text-align: center;
        }}
        
        .close {{
            color: #ff3366;
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
        }}
        
        .close:hover {{
            color: #ff0000;
        }}
        
        #modalImage {{
            max-width: 100%;
            max-height: 70vh;
            border: 2px solid #00ff88;
            border-radius: 10px;
        }}
        
        .screenshot-thumb {{
            width: 200px;
            height: 150px;
            object-fit: cover;
            border: 2px solid #00ff88;
            border-radius: 10px;
            cursor: pointer;
            transition: all 0.3s ease;
            margin: 5px;
        }}
        
        .screenshot-thumb:hover {{
            transform: scale(1.05);
            box-shadow: 0 0 20px rgba(0, 255, 136, 0.5);
        }}
        
        .web-services-section {{
            margin-top: 20px;
        }}
        
        .service-item {{
            display: flex;
            align-items: center;
            gap: 15px;
            padding: 10px;
            background: rgba(0, 255, 136, 0.05);
            border-radius: 8px;
            margin-bottom: 10px;
        }}
        
        .service-info {{
            flex: 1;
        }}
        
        .service-url {{
            color: #66ffaa;
            text-decoration: none;
            font-weight: bold;
        }}
        
        .service-url:hover {{
            color: #00ff88;
        }}
        
        /* Hide elements */
        .hidden {{
            display: none !important;
        }}
        
        /* Responsive design */
        @media (max-width: 768px) {{
            h1 {{ font-size: 2.5rem; }}
            .stats {{ grid-template-columns: 1fr; }}
            .cve-summary {{ grid-template-columns: repeat(2, 1fr); }}
            .filter-controls {{ flex-direction: column; }}
            .dashboard-stats {{ flex-direction: column; gap: 15px; }}
        }}
    </style>
</head>
<body>
    <div class="matrix-bg"></div>
    <div class="container">
        <div class="header">
            <h1 class="glitch"><i class="fas fa-skull"></i> LAZYHUNTER</h1>
            <div class="subtitle">CyberSec Intelligence & Threat Analysis</div>
            <div class="timestamp">
                <i class="fas fa-clock"></i> Scan Completed: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            </div>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value"><i class="fas fa-crosshairs"></i> {total_ips}</div>
                <div class="stat-label">Targets Analyzed</div>
            </div>
            <div class="stat-card">
                <div class="stat-value"><i class="fas fa-bug"></i> {total_cves}</div>
                <div class="stat-label">Total CVEs</div>
            </div>
            <div class="stat-card critical">
                <div class="stat-value critical"><i class="fas fa-exclamation-triangle"></i> {critical_cves}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="stat-value high"><i class="fas fa-fire"></i> {high_cves}</div>
                <div class="stat-label">High Risk</div>
            </div>
        </div>
        
        <div class="content">
            <!-- Search and Filter Controls -->
            <div class="controls-section">
                <div class="search-container">
                    <input type="text" id="searchInput" placeholder="🔍 Search IPs, CVEs, hostnames..." class="search-input">
                    <button id="clearSearch" class="clear-btn"><i class="fas fa-times"></i></button>
                </div>
                <div class="filter-controls">
                    <select id="severityFilter" class="filter-select">
                        <option value="">All Severities</option>
                        <option value="critical">Critical Only</option>
                        <option value="high">High Risk Only</option>
                        <option value="medium">Medium Risk Only</option>
                        <option value="low">Low Risk Only</option>
                    </select>
                    <select id="sortBy" class="filter-select">
                        <option value="ip">Sort by IP</option>
                        <option value="cves">Sort by CVE Count</option>
                        <option value="critical">Sort by Critical CVEs</option>
                        <option value="ports">Sort by Port Count</option>
                    </select>
                    <button id="toggleView" class="view-toggle"><i class="fas fa-th-large"></i> Grid View</button>
                </div>
            </div>
            
            <h2 class="section-title"><i class="fas fa-search"></i> THREAT INTELLIGENCE</h2>
            
            <!-- Dashboard Stats -->
            <div class="dashboard-stats" id="filteredStats">
                <div class="quick-stat">
                    <span class="stat-number" id="visibleCount">{total_ips}</span>
                    <span class="stat-desc">Visible Targets</span>
                </div>
                <div class="quick-stat">
                    <span class="stat-number" id="webServicesCount">0</span>
                    <span class="stat-desc">Web Services</span>
                </div>
                <div class="quick-stat">
                    <span class="stat-number" id="criticalVisible">0</span>
                    <span class="stat-desc">Critical Issues</span>
                </div>
            </div>
            
            <!-- Results Container -->
            <div id="resultsContainer" class="results-grid">
                {self._generate_ip_cards_cyberpunk()}
            </div>
            
            <!-- Screenshot Modal -->
            <div id="screenshotModal" class="modal">
                <div class="modal-content">
                    <span class="close">&times;</span>
                    <h3 id="modalTitle">Screenshot</h3>
                    <img id="modalImage" src="" alt="Screenshot">
                    <div id="modalInfo"></div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // Matrix rain effect
        function createMatrixRain() {{
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            document.querySelector('.matrix-bg').appendChild(canvas);
            
            canvas.style.position = 'absolute';
            canvas.style.top = '0';
            canvas.style.left = '0';
            canvas.style.zIndex = '-1';
            canvas.style.opacity = '0.1';
            
            function resizeCanvas() {{
                canvas.width = window.innerWidth;
                canvas.height = window.innerHeight;
            }}
            
            resizeCanvas();
            window.addEventListener('resize', resizeCanvas);
            
            const chars = "01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン";
            const fontSize = 14;
            const columns = Math.floor(canvas.width / fontSize);
            const drops = Array(columns).fill(1);
            
            function draw() {{
                ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
                ctx.fillRect(0, 0, canvas.width, canvas.height);
                
                ctx.fillStyle = '#00ff88';
                ctx.font = fontSize + 'px monospace';
                
                for (let i = 0; i < drops.length; i++) {{
                    const text = chars[Math.floor(Math.random() * chars.length)];
                    ctx.fillText(text, i * fontSize, drops[i] * fontSize);
                    
                    if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {{
                        drops[i] = 0;
                    }}
                    drops[i]++;
                }}
            }}
            
            setInterval(draw, 33);
        }}
        
        // Initialize effects
        document.addEventListener('DOMContentLoaded', function() {{
            createMatrixRain();
            
            // Animate stat cards
            const statCards = document.querySelectorAll('.stat-card');
            statCards.forEach((card, index) => {{
                setTimeout(() => {{
                    card.style.opacity = '0';
                    card.style.transform = 'translateY(20px)';
                    card.style.transition = 'all 0.6s ease';
                    setTimeout(() => {{
                        card.style.opacity = '1';
                        card.style.transform = 'translateY(0)';
                    }}, 100);
                }}, index * 200);
            }});
            
            // CVE severity highlighting
            document.querySelectorAll('.cve-item').forEach(item => {{
                item.addEventListener('mouseenter', function() {{
                    this.style.background = 'rgba(0, 255, 136, 0.1)';
                }});
                item.addEventListener('mouseleave', function() {{
                    this.style.background = 'rgba(0, 0, 0, 0.3)';
                }});
            }});
            
            // Initialize dashboard functionality
            initializeDashboard();
            updateFilteredStats();
        }});
        
        // Dashboard functionality
        function initializeDashboard() {{
            const searchInput = document.getElementById('searchInput');
            const clearSearch = document.getElementById('clearSearch');
            const severityFilter = document.getElementById('severityFilter');
            const sortBy = document.getElementById('sortBy');
            const toggleView = document.getElementById('toggleView');
            
            // Search functionality
            searchInput.addEventListener('input', filterAndSearch);
            clearSearch.addEventListener('click', () => {{
                searchInput.value = '';
                filterAndSearch();
            }});
            
            // Filter functionality
            severityFilter.addEventListener('change', filterAndSearch);
            sortBy.addEventListener('change', filterAndSearch);
            
            // View toggle
            toggleView.addEventListener('click', toggleViewMode);
            
            // Modal functionality
            const modal = document.getElementById('screenshotModal');
            const closeModal = modal.querySelector('.close');
            closeModal.addEventListener('click', () => modal.style.display = 'none');
            window.addEventListener('click', (e) => {{
                if (e.target === modal) modal.style.display = 'none';
            }});
        }}
        
        function filterAndSearch() {{
            const searchTerm = document.getElementById('searchInput').value.toLowerCase();
            const severity = document.getElementById('severityFilter').value;
            const sortOrder = document.getElementById('sortBy').value;
            
            const cards = Array.from(document.querySelectorAll('.ip-card'));
            let visibleCards = [];
            
            cards.forEach(card => {{
                let visible = true;
                const cardText = card.textContent.toLowerCase();
                
                // Search filter
                if (searchTerm && !cardText.includes(searchTerm)) {{
                    visible = false;
                }}
                
                // Severity filter
                if (severity) {{
                    const hasSeverity = card.querySelector(`.cve-${{severity}}`);
                    if (!hasSeverity) visible = false;
                }}
                
                if (visible) {{
                    card.style.display = 'block';
                    visibleCards.push(card);
                }} else {{
                    card.style.display = 'none';
                }}
            }});
            
            // Sort visible cards
            if (sortOrder && visibleCards.length > 0) {{
                sortCards(visibleCards, sortOrder);
            }}
            
            updateFilteredStats();
        }}
        
        function sortCards(cards, sortBy) {{
            const container = document.getElementById('resultsContainer');
            
            cards.sort((a, b) => {{
                switch (sortBy) {{
                    case 'ip':
                        const ipA = a.querySelector('.ip-address').textContent.trim();
                        const ipB = b.querySelector('.ip-address').textContent.trim();
                        return ipA.localeCompare(ipB);
                    
                    case 'cves':
                        const cvesA = a.querySelectorAll('.cve-item').length;
                        const cvesB = b.querySelectorAll('.cve-item').length;
                        return cvesB - cvesA;
                    
                    case 'critical':
                        const criticalA = parseInt(a.querySelector('.stat-value.critical')?.textContent || '0');
                        const criticalB = parseInt(b.querySelector('.stat-value.critical')?.textContent || '0');
                        return criticalB - criticalA;
                    
                    case 'ports':
                        const portsA = a.querySelectorAll('.port-badge').length;
                        const portsB = b.querySelectorAll('.port-badge').length;
                        return portsB - portsA;
                    
                    default:
                        return 0;
                }}
            }});
            
            // Reorder DOM elements
            cards.forEach(card => container.appendChild(card));
        }}
        
        function updateFilteredStats() {{
            const visibleCards = document.querySelectorAll('.ip-card[style*="display: block"], .ip-card:not([style*="display: none"])');
            let totalCritical = 0;
            let totalWebServices = 0;
            
            visibleCards.forEach(card => {{
                // Count critical CVEs
                const criticalElement = card.querySelector('.stat-value.critical');
                if (criticalElement) {{
                    totalCritical += parseInt(criticalElement.textContent) || 0;
                }}
                
                // Count web services
                const webServices = card.querySelectorAll('.service-item');
                totalWebServices += webServices.length;
            }});
            
            // Update stats display
            document.getElementById('visibleCount').textContent = visibleCards.length;
            document.getElementById('webServicesCount').textContent = totalWebServices;
            document.getElementById('criticalVisible').textContent = totalCritical;
        }}
        
        function toggleViewMode() {{
            const toggleBtn = document.getElementById('toggleView');
            const resultsContainer = document.getElementById('resultsContainer');
            
            if (resultsContainer.classList.contains('results-grid')) {{
                // Switch to table view
                resultsContainer.className = 'results-table';
                toggleBtn.innerHTML = '<i class="fas fa-th"></i> Card View';
                generateTableView();
            }} else {{
                // Switch to grid view
                resultsContainer.className = 'results-grid';
                toggleBtn.innerHTML = '<i class="fas fa-th-large"></i> Grid View';
                location.reload(); // Reload to restore grid view
            }}
        }}
        
        function generateTableView() {{
            const cards = document.querySelectorAll('.ip-card');
            let tableHTML = `
                <table>
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Hostnames</th>
                            <th>Ports</th>
                            <th>Critical CVEs</th>
                            <th>High CVEs</th>
                            <th>Total CVEs</th>
                            <th>Web Services</th>
                        </tr>
                    </thead>
                    <tbody>
            `;
            
            cards.forEach(card => {{
                if (card.style.display === 'none') return;
                
                const ip = card.querySelector('.ip-address').textContent.trim();
                const hostnames = card.querySelector('.hostname').textContent.trim();
                const ports = card.querySelectorAll('.port-badge').length;
                const critical = parseInt(card.querySelector('.stat-value.critical')?.textContent || '0');
                const high = parseInt(card.querySelector('.stat-value.high')?.textContent || '0');
                const totalCves = card.querySelectorAll('.cve-item').length;
                const webServices = card.querySelectorAll('.service-item').length;
                
                tableHTML += `
                    <tr>
                        <td>${{ip}}</td>
                        <td>${{hostnames}}</td>
                        <td>${{ports}}</td>
                        <td class="critical">${{critical}}</td>
                        <td class="high">${{high}}</td>
                        <td>${{totalCves}}</td>
                        <td>${{webServices}}</td>
                    </tr>
                `;
            }});
            
            tableHTML += '</tbody></table>';
            document.getElementById('resultsContainer').innerHTML = tableHTML;
        }}
        
        // Screenshot modal functionality
        function showScreenshot(imgElement, url, title) {{
            const modal = document.getElementById('screenshotModal');
            const modalImage = document.getElementById('modalImage');
            const modalTitle = document.getElementById('modalTitle');
            const modalInfo = document.getElementById('modalInfo');
            
            modalImage.src = imgElement.src;
            modalTitle.textContent = `Screenshot: ${{title}}`;
            modalInfo.innerHTML = `
                <p><strong>URL:</strong> <a href="${{url}}" target="_blank" style="color: #66ffaa;">${{url}}</a></p>
                <p><strong>Captured:</strong> ${{new Date().toLocaleString()}}</p>
            `;
            
            modal.style.display = 'block';
        }}
    </script>
</body>
</html>
        """
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"📊 HTML report generated: {output_file}")
            
            # Auto-open HTML report
            if auto_open:
                try:
                    import webbrowser
                    webbrowser.open(f'file://{os.path.abspath(output_file)}')
                    logger.info(f"🌐 Opening report in browser: {output_file}")
                except Exception as e:
                    logger.warning(f"Could not auto-open browser: {e}")
            
            return output_file
            
        except Exception as e:
            logger.error(f"Error generating HTML report: {e}")
            return ""
    
    def _generate_ip_cards(self) -> str:
        """Generate HTML cards for each IP"""
        cards = []
        
        for result in self.results:
            # Port badges
            port_badges = []
            if result.ports:
                port_badges = [f'<span class="port-badge">{port}</span>' for port in result.ports]
            
            # CVE items
            cve_items = []
            if result.vulns:
                for cve in result.vulns:
                    cvss = cve.get('cvss', 0)
                    if cvss >= 9.0:
                        cve_class = 'cve-critical'
                    elif cvss >= 7.0:
                        cve_class = 'cve-high'
                    elif cvss >= 4.0:
                        cve_class = 'cve-medium'
                    else:
                        cve_class = 'cve-low'
                    
                    cve_items.append(f'''
                    <div class="cve-item {cve_class}">
                        <strong>{cve['id']}</strong> - CVSS: {cvss}<br>
                        <small>{cve.get('summary', 'No description available')}</small>
                    </div>
                    ''')
            
            card = f'''
            <div class="ip-card">
                <div class="ip-header">
                    <h3>🌐 {result.ip}</h3>
                    <p><strong>Hostnames:</strong> {', '.join(result.hostnames) if result.hostnames else 'None'}</p>
                </div>
                <div class="ip-details">
                    <div style="margin-bottom: 15px;">
                        <strong>Open Ports:</strong><br>
                        <div class="port-list">
                            {' '.join(port_badges) if port_badges else 'None detected'}
                        </div>
                    </div>
                    
                    <div>
                        <strong>CVE Summary:</strong> Critical: {result.critical_cves}, High: {result.high_risk_cves}, 
                        Medium: {result.medium_risk_cves}, Low: {result.low_risk_cves}
                    </div>
                    
                    {f'<div class="cve-list">{"".join(cve_items)}</div>' if cve_items else '<p>No CVEs found</p>'}
                </div>
            </div>
            '''
            cards.append(card)
        
        return ''.join(cards)
    
    def _generate_ip_cards_cyberpunk(self) -> str:
        """Generate cyberpunk-styled HTML cards for each IP"""
        cards = []
        
        for result in self.results:
            # Port badges
            port_badges = []
            if result.ports:
                port_badges = [f'<span class="port-badge">{port}</span>' for port in result.ports]
            
            # CVE items with enhanced styling
            cve_items = []
            if result.vulns:
                for cve in result.vulns:
                    cvss = cve.get('cvss', 0)
                    if cvss >= 9.0:
                        cve_class = 'cve-critical'
                        severity_icon = 'fas fa-skull'
                    elif cvss >= 7.0:
                        cve_class = 'cve-high'
                        severity_icon = 'fas fa-fire'
                    elif cvss >= 4.0:
                        cve_class = 'cve-medium'
                        severity_icon = 'fas fa-exclamation-triangle'
                    else:
                        cve_class = 'cve-low'
                        severity_icon = 'fas fa-info-circle'
                    
                    cve_items.append(f'''
                    <div class="cve-item {cve_class}">
                        <div class="cve-header">
                            <span class="cve-id"><i class="{severity_icon}"></i> {cve['id']}</span>
                            <span class="cvss-score">CVSS: {cvss}</span>
                        </div>
                        <div class="cve-summary-text">{cve.get('summary', 'No description available')}</div>
                    </div>
                    ''')
            
            card = f'''
            <div class="ip-card">
                <div class="ip-header">
                    <div class="ip-address"><i class="fas fa-globe"></i> {result.ip}</div>
                    <div class="hostname">
                        <i class="fas fa-server"></i> {', '.join(result.hostnames) if result.hostnames else 'No hostnames detected'}
                    </div>
                </div>
                <div class="ip-details">
                    <div class="detail-section">
                        <div class="detail-title"><i class="fas fa-network-wired"></i> Open Ports</div>
                        <div class="port-list">
                            {' '.join(port_badges) if port_badges else '<span class="no-data">No open ports detected</span>'}
                        </div>
                    </div>
                    
                    <div class="detail-section">
                        <div class="detail-title"><i class="fas fa-chart-bar"></i> CVE Summary</div>
                        <div class="cve-summary">
                            <div class="cve-count critical">
                                <div class="stat-value critical">{result.critical_cves}</div>
                                <div>Critical</div>
                            </div>
                            <div class="cve-count high">
                                <div class="stat-value high">{result.high_risk_cves}</div>
                                <div>High</div>
                            </div>
                            <div class="cve-count medium">
                                <div class="stat-value medium">{result.medium_risk_cves}</div>
                                <div>Medium</div>
                            </div>
                            <div class="cve-count low">
                                <div class="stat-value low">{result.low_risk_cves}</div>
                                <div>Low</div>
                            </div>
                        </div>
                    </div>
                    
                    {('<div class="detail-section"><div class="detail-title"><i class="fas fa-bug"></i> Vulnerability Details</div><div class="cve-list">' + "".join(cve_items) + '</div></div>') if cve_items else '<div class="no-data"><i class="fas fa-shield-alt"></i> No vulnerabilities detected</div>'}
                    
                    {self._generate_web_services_section(result)}
                </div>
            </div>
            '''
            cards.append(card)
        
        return ''.join(cards)
    
    def _generate_web_services_section(self, result: IPAnalysisResult) -> str:
        """Generate web services section with screenshots"""
        if not result.web_services:
            return ""
        
        services_html = []
        for service in result.web_services:
            screenshot_html = ""
            if service.get('screenshot'):
                screenshot_html = f'''
                <img src="data:image/png;base64,{service['screenshot']}" 
                     class="screenshot-thumb" 
                     onclick="showScreenshot(this, '{service['url']}', '{service.get('title', 'Unknown')}')">
                '''
            
            services_html.append(f'''
            <div class="service-item">
                <div class="service-info">
                    <a href="{service['url']}" target="_blank" class="service-url">
                        <i class="fas fa-globe"></i> {service['url']}
                    </a>
                    <div style="font-size: 0.9rem; color: #888;">
                        {service.get('title', 'No title')} | {service.get('server', 'Unknown server')}
                    </div>
                </div>
                {screenshot_html}
            </div>
            ''')
        
        return f'''
        <div class="detail-section web-services-section">
            <div class="detail-title"><i class="fas fa-desktop"></i> Web Services ({len(result.web_services)})</div>
            {"".join(services_html)}
        </div>
        '''
    
    def display_summary(self):
        """Display enhanced analysis summary"""
        if not self.results:
            print(f"{YELLOW}[INFO]{RESET} No results to display")
            return
        
        total_ips = len(self.results)
        total_cves = sum(r.total_cves for r in self.results)
        critical_cves = sum(r.critical_cves for r in self.results)
        high_cves = sum(r.high_risk_cves for r in self.results)
        
        print(f"\n{CYAN}{'='*60}{RESET}")
        print(f"{BOLD}🎯 Enhanced LazyHunter Analysis Summary{RESET}")
        print(f"{CYAN}{'='*60}{RESET}")
        print(f"📊 Total IPs Analyzed: {GREEN}{total_ips}{RESET}")
        print(f"🔍 Total CVEs Found: {YELLOW}{total_cves}{RESET}")
        print(f"🚨 Critical CVEs: {RED}{critical_cves}{RESET}")
        print(f"⚠️  High Risk CVEs: {YELLOW}{high_cves}{RESET}")
        print(f"{CYAN}{'='*60}{RESET}\n")

def main():
    """Enhanced main function with better CLI"""
    os.system("clear")
    print(BANNER)
    
    parser = argparse.ArgumentParser(description="Enhanced LazyHunter - Advanced IP Reconnaissance Tool")
    parser.add_argument("target", nargs='?', help="Path to a file containing IPs or a single IP address. If omitted, will run in demo mode with localhost.")
    parser.add_argument("--cves", action="store_true", help="Show CVEs only")
    parser.add_argument("--ports", action="store_true", help="Show open ports only")
    parser.add_argument("--host", action="store_true", help="Show hostnames only")
    parser.add_argument("--cve+ports", dest="cve_ports", action="store_true", help="Show CVEs with ports")
    parser.add_argument("--json-output", help="Output JSON report file")
    parser.add_argument("--html-output", help="Output HTML report file") 
    parser.add_argument("--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout (default: 30)")
    parser.add_argument("--quiet", action="store_true", help="Quiet mode - minimal output")
    parser.add_argument("--no-auto-open", action="store_true", help="Disable auto-opening HTML report in browser")
    parser.add_argument("--screenshots", action="store_true", help="Enable web service screenshot capture (requires selenium)")
    
    args = parser.parse_args()
    
    # Initialize hunter
    hunter = EnhancedLazyHunter(timeout=args.timeout, capture_screenshots=args.screenshots)
    
    if args.screenshots:
        engines_available = []
        missing_engines = []
        
        if PLAYWRIGHT_AVAILABLE:
            engines_available.append("Playwright")
        else:
            missing_engines.append("playwright")
            
        if SELENIUM_AVAILABLE:
            engines_available.append("Selenium")
        else:
            missing_engines.append("selenium webdriver-manager")
            
        if PUPPETEER_AVAILABLE:
            engines_available.append("Puppeteer")
        else:
            missing_engines.append("pyppeteer")
        
        if engines_available:
            print(f"{GREEN}[✓] Screenshot engines available: {', '.join(engines_available)}{RESET}")
        else:
            print(f"{RED}[✗] No screenshot engines available!{RESET}")
            print(f"{YELLOW}[INFO] Install with: pip install {' '.join(missing_engines)}{RESET}")
        
        if missing_engines:
            print(f"{YELLOW}[INFO] Additional engines: pip install {' '.join(missing_engines)}{RESET}")
    
    if args.target:
        if os.path.isfile(args.target):
            print(f"{YELLOW}[INFO]{RESET} Target File: {os.path.basename(args.target)}")
            hunter.analyze_ips_from_file(args.target, max_workers=args.threads)
        else:
            print(f"{YELLOW}[INFO]{RESET} Target: {args.target}")
            result = hunter.analyze_single_ip(args.target)
            if result:
                hunter.results.append(result)
                if not args.quiet:
                    hunter._display_result(result)
    else:
        print(f"{YELLOW}[INFO]{RESET} Demo mode - analyzing localhost")
        result = hunter.analyze_single_ip("127.0.0.1")
        if result:
            hunter.results.append(result)

    # Generate reports
    if args.json_output:
        hunter.generate_json_report(args.json_output)
    
    # Auto-generate HTML report if results found or explicitly requested
    if args.html_output or (hunter.results and not args.quiet):
        output_file = args.html_output if args.html_output else None
        auto_open = not args.no_auto_open
        html_file = hunter.generate_html_report(output_file, auto_open=auto_open)
        if html_file and not args.html_output:
            print(f"{GREEN}[✓] Auto-generated HTML report: {html_file}{RESET}")
    
    # Display summary
    if not args.quiet:
        hunter.display_summary()
    
    # Cleanup screenshot engines
    if args.screenshots:
        hunter.cleanup()

if __name__ == "__main__":
    main()

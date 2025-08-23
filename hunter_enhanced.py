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
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys

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
BANNER += "║               🕵️  Enhanced LazyHunter v2.0 🕵️                   ║\n"
BANNER += "║                                                                  ║\n"
BANNER += "║          Advanced IP Reconnaissance & CVE Analysis               ║\n"
BANNER += "║             Orchestrator Integration Ready                       ║\n"
BANNER += "║                                                                  ║\n"
BANNER += "╚══════════════════════════════════════════════════════════════════╝\n"
BANNER += f"{RESET}"

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

def signal_handler(sig, frame):
    """Enhanced signal handler"""
    choice = input(f"\n{YELLOW}Do you want to quit? (y/n): {RESET}")
    if choice.lower() == 'y':
        print(f"{RED}Exiting Enhanced LazyHunter...{RESET}")
        exit(0)

signal.signal(signal.SIGINT, signal_handler)

class EnhancedLazyHunter:
    """Enhanced LazyHunter with orchestrator integration"""
    
    def __init__(self, rate_limit: int = 10, timeout: int = 30):
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.results: List[IPAnalysisResult] = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Enhanced-LazyHunter/2.0'
        })
        
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
                        'id': cve_id,
                        'cvss': cvss_score,
                        'summary': cve_info.get('summary', '')[:200],  # Truncate
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
        
        return result
    
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
    
    def generate_html_report(self, output_file: str = None) -> str:
        """Generate HTML report with enhanced visualization"""
        if output_file is None:
            output_file = f"hunter_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        # Calculate statistics
        total_ips = len(self.results)
        total_cves = sum(r.total_cves for r in self.results)
        critical_cves = sum(r.critical_cves for r in self.results)
        high_cves = sum(r.high_risk_cves for r in self.results)
        
        # Generate HTML content
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enhanced LazyHunter Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f8f9fa; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); overflow: hidden; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; padding: 30px; background: #f8f9fa; }}
        .stat-card {{ text-align: center; padding: 20px; background: white; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        .stat-value {{ font-size: 2rem; font-weight: bold; margin-bottom: 5px; }}
        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #28a745; }}
        .content {{ padding: 30px; }}
        .ip-card {{ background: white; border: 1px solid #dee2e6; border-radius: 8px; margin-bottom: 20px; overflow: hidden; }}
        .ip-header {{ background: #f8f9fa; padding: 15px; border-bottom: 1px solid #dee2e6; }}
        .ip-details {{ padding: 20px; }}
        .cve-list {{ max-height: 300px; overflow-y: auto; }}
        .cve-item {{ padding: 10px; border-left: 4px solid #dee2e6; margin-bottom: 10px; background: #f8f9fa; }}
        .cve-critical {{ border-left-color: #dc3545; }}
        .cve-high {{ border-left-color: #fd7e14; }}
        .cve-medium {{ border-left-color: #ffc107; }}
        .cve-low {{ border-left-color: #28a745; }}
        h2 {{ color: #495057; margin-bottom: 20px; }}
        .port-list {{ display: flex; flex-wrap: wrap; gap: 5px; }}
        .port-badge {{ background: #007bff; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.8rem; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🕵️ Enhanced LazyHunter Report</h1>
            <p>IP Reconnaissance & CVE Analysis</p>
            <p>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">{total_ips}</div>
                <div class="stat-label">IPs Analyzed</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{total_cves}</div>
                <div class="stat-label">Total CVEs</div>
            </div>
            <div class="stat-card critical">
                <div class="stat-value">{critical_cves}</div>
                <div class="stat-label">Critical CVEs</div>
            </div>
            <div class="stat-card high">
                <div class="stat-value">{high_cves}</div>
                <div class="stat-label">High Risk CVEs</div>
            </div>
        </div>
        
        <div class="content">
            <h2>🎯 IP Analysis Results</h2>
            {self._generate_ip_cards()}
        </div>
    </div>
</body>
</html>
        """
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"📊 HTML report generated: {output_file}")
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
    
    args = parser.parse_args()
    
    # Initialize hunter
    hunter = EnhancedLazyHunter(timeout=args.timeout)
    
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
    
    if args.html_output:
        hunter.generate_html_report(args.html_output)
    
    # Display summary
    if not args.quiet:
        hunter.display_summary()

if __name__ == "__main__":
    main()
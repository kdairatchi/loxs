#!/usr/bin/env python3
# ABOUTME: Enhanced LOXS scanner with automated integration for filter.sh reconnaissance data
# ABOUTME: Processes URLs from reconnaissance phase and performs targeted vulnerability scanning with improved automation

import os
import sys
import json
import argparse
import logging
import time
import requests
import asyncio
import aiohttp
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin
import random
import re

# Enhanced logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class Colors:
    """ANSI color codes"""
    BLUE = '\033[94m'
    GREEN = '\033[1;92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    ORANGE = '\033[38;5;208m'
    BOLD = '\033[1m'

@dataclass
class VulnerabilityResult:
    """Data structure for vulnerability findings"""
    url: str
    vulnerability_type: str
    payload: str
    evidence: str
    severity: str
    timestamp: str
    response_time: float = 0.0
    status_code: int = 0

class EnhancedLOXS:
    """Enhanced LOXS Scanner with Automation"""
    
    def __init__(self, threads: int = 50, timeout: int = 10):
        self.threads = threads
        self.timeout = timeout
        self.results: List[VulnerabilityResult] = []
        self.session = requests.Session()
        
        # Configure session
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # Load payloads
        self.payloads = self._load_payloads()
        
        # Statistics
        self.stats = {
            'total_scanned': 0,
            'vulnerabilities_found': 0,
            'scan_start': None,
            'scan_end': None
        }
    
    def _load_payloads(self) -> Dict[str, List[str]]:
        """Load vulnerability payloads from files"""
        payloads = {}
        payload_dir = Path(__file__).parent / "payloads"
        
        payload_files = {
            'lfi': 'lfi.txt',
            'xss': 'xss.txt', 
            'sqli': ['sqli/mysql.txt', 'sqli/postgresql.txt', 'sqli/generic.txt'],
            'or': 'or.txt'
        }
        
        for vuln_type, files in payload_files.items():
            payloads[vuln_type] = []
            
            if isinstance(files, str):
                files = [files]
                
            for file_path in files:
                full_path = payload_dir / file_path
                if full_path.exists():
                    try:
                        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                            file_payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                            payloads[vuln_type].extend(file_payloads)
                    except Exception as e:
                        logger.warning(f"Could not load payloads from {full_path}: {e}")
        
        logger.info(f"Loaded payloads: {[(k, len(v)) for k, v in payloads.items()]}")
        return payloads
    
    def scan_urls_from_file(self, file_path: str, scan_types: List[str] = None) -> List[VulnerabilityResult]:
        """Scan URLs from a file (orchestrator integration)"""
        if scan_types is None:
            scan_types = ['lfi', 'xss', 'sqli', 'or']
            
        logger.info(f"🎯 Loading URLs from file: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in f if line.strip()]
                
            if not urls:
                logger.warning("No URLs found in file")
                return []
                
            logger.info(f"Loaded {len(urls)} URLs for scanning")
            return self.scan_urls(urls, scan_types)
            
        except FileNotFoundError:
            logger.error(f"URL file not found: {file_path}")
            return []
        except Exception as e:
            logger.error(f"Error loading URLs from file: {e}")
            return []
    
    def scan_urls(self, urls: List[str], scan_types: List[str]) -> List[VulnerabilityResult]:
        """Scan multiple URLs for vulnerabilities"""
        self.stats['scan_start'] = datetime.now()
        self.stats['total_scanned'] = len(urls)
        
        logger.info(f"🚀 Starting enhanced vulnerability scan on {len(urls)} URLs")
        logger.info(f"Scan types: {', '.join(scan_types)}")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_url = {}
            
            for url in urls:
                for scan_type in scan_types:
                    future = executor.submit(self._scan_url_for_vulnerability, url, scan_type)
                    future_to_url[future] = (url, scan_type)
            
            # Process results as they complete
            for future in as_completed(future_to_url):
                url, scan_type = future_to_url[future]
                try:
                    results = future.result()
                    self.results.extend(results)
                    
                    if results:
                        logger.info(f"🎯 {Colors.RED}VULNERABILITY FOUND{Colors.RESET} - {scan_type.upper()} in {url}")
                        
                except Exception as e:
                    logger.error(f"Error scanning {url} for {scan_type}: {e}")
        
        self.stats['scan_end'] = datetime.now()
        self.stats['vulnerabilities_found'] = len(self.results)
        
        logger.info(f"✅ Scan completed! Found {len(self.results)} vulnerabilities")
        return self.results
    
    def _scan_url_for_vulnerability(self, url: str, vuln_type: str) -> List[VulnerabilityResult]:
        """Scan a single URL for a specific vulnerability type"""
        results = []
        
        if vuln_type not in self.payloads:
            return results
            
        payloads = self.payloads[vuln_type]
        if not payloads:
            return results
            
        # Randomly sample payloads for efficiency (max 5 per type)
        test_payloads = random.sample(payloads, min(len(payloads), 5))
        
        for payload in test_payloads:
            try:
                start_time = time.time()
                
                # Inject payload based on vulnerability type
                test_url = self._inject_payload(url, payload, vuln_type)
                
                response = self.session.get(
                    test_url,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=False if vuln_type == 'or' else True
                )
                
                response_time = time.time() - start_time
                
                # Check for vulnerability indicators
                if self._check_vulnerability_indicators(response, payload, vuln_type):
                    evidence = self._extract_evidence(response, payload, vuln_type)
                    severity = self._determine_severity(vuln_type, evidence)
                    
                    result = VulnerabilityResult(
                        url=url,
                        vulnerability_type=vuln_type,
                        payload=payload,
                        evidence=evidence[:500],  # Truncate evidence
                        severity=severity,
                        timestamp=datetime.now().isoformat(),
                        response_time=response_time,
                        status_code=response.status_code
                    )
                    
                    results.append(result)
                    break  # Found vulnerability, no need to test more payloads
                    
            except requests.exceptions.Timeout:
                continue
            except requests.exceptions.RequestException:
                continue
            except Exception as e:
                logger.debug(f"Error testing {vuln_type} on {url}: {e}")
                continue
                
        return results
    
    def _inject_payload(self, url: str, payload: str, vuln_type: str) -> str:
        """Inject payload into URL based on vulnerability type"""
        if '?' not in url:
            return url
            
        if vuln_type == 'or':
            # Open redirect - replace parameter values
            return re.sub(r'=[^&]*', f'={payload}', url)
        elif vuln_type == 'lfi':
            # Local file inclusion - replace parameter values
            return re.sub(r'=[^&]*', f'={payload}', url)
        elif vuln_type in ['xss', 'sqli']:
            # XSS and SQLi - replace parameter values
            return re.sub(r'=[^&]*', f'={payload}', url)
        else:
            return re.sub(r'=[^&]*', f'={payload}', url)
    
    def _check_vulnerability_indicators(self, response: requests.Response, payload: str, vuln_type: str) -> bool:
        """Check if response indicates vulnerability"""
        content = response.text.lower()
        
        indicators = {
            'lfi': [
                'root:x:', '/etc/passwd', 'www-data', 'daemon:', 'bin:',
                '[boot loader]', 'windows', 'windir'
            ],
            'xss': [
                payload.lower(), '<script', 'javascript:', 'onerror=', 'onload='
            ],
            'sqli': [
                'mysql_fetch', 'ora-01', 'microsoft ole db', 'odbc', 
                'sql syntax', 'mysql_num_rows', 'pg_exec', 'warning: mysql',
                'unknown column', 'table doesn\'t exist'
            ],
            'or': []  # Open redirect checked differently
        }
        
        if vuln_type == 'or':
            # Check for redirect status codes and location header
            if response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get('Location', '')
                return payload in location
            return False
        
        # Check content for indicators
        vuln_indicators = indicators.get(vuln_type, [])
        for indicator in vuln_indicators:
            if indicator in content:
                return True
                
        return False
    
    def _extract_evidence(self, response: requests.Response, payload: str, vuln_type: str) -> str:
        """Extract evidence of vulnerability"""
        if vuln_type == 'or':
            return f"Status: {response.status_code}, Location: {response.headers.get('Location', '')}"
        
        # Find relevant portion of response containing payload or indicators
        content = response.text
        
        # Try to find payload in response
        if payload in content:
            # Extract surrounding context
            index = content.find(payload)
            start = max(0, index - 100)
            end = min(len(content), index + len(payload) + 100)
            return content[start:end]
        
        # Return first portion of response
        return content[:200]
    
    def _determine_severity(self, vuln_type: str, evidence: str) -> str:
        """Determine vulnerability severity"""
        severity_map = {
            'lfi': 'High',
            'sqli': 'Critical',
            'xss': 'Medium',
            'or': 'Medium'
        }
        return severity_map.get(vuln_type, 'Low')
    
    def scan_gf_patterns(self, gf_results_dir: str) -> List[VulnerabilityResult]:
        """Scan URLs from GF pattern results"""
        logger.info(f"🔍 Scanning GF pattern results from: {gf_results_dir}")
        
        gf_dir = Path(gf_results_dir)
        if not gf_dir.exists():
            logger.warning("GF results directory not found")
            return []
        
        pattern_files = {
            'lfi': 'local-file-inclusion.txt',
            'xss': 'cross-site-scripting.txt',
            'sqli': 'sql-injection.txt',
            'or': 'open-redirect.txt'
        }
        
        all_results = []
        
        for vuln_type, filename in pattern_files.items():
            file_path = gf_dir / filename
            if file_path.exists():
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        urls = [line.strip() for line in f if line.strip()]
                    
                    if urls:
                        logger.info(f"Scanning {len(urls)} URLs for {vuln_type}")
                        results = self.scan_urls(urls, [vuln_type])
                        all_results.extend(results)
                        
                except Exception as e:
                    logger.error(f"Error processing GF pattern file {file_path}: {e}")
        
        return all_results
    
    def generate_report(self, output_file: str = None) -> str:
        """Generate vulnerability report"""
        if output_file is None:
            output_file = f"loxs_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        # Group results by vulnerability type
        grouped_results = {}
        for result in self.results:
            if result.vulnerability_type not in grouped_results:
                grouped_results[result.vulnerability_type] = []
            grouped_results[result.vulnerability_type].append(result)
        
        # Calculate statistics
        scan_duration = 0
        if self.stats['scan_start'] and self.stats['scan_end']:
            scan_duration = (self.stats['scan_end'] - self.stats['scan_start']).total_seconds()
        
        # Generate HTML report
        html_content = self._generate_html_report(grouped_results, scan_duration)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"📊 Report generated: {output_file}")
        return output_file
    
    def _generate_html_report(self, grouped_results: Dict, scan_duration: float) -> str:
        """Generate HTML report content"""
        severity_colors = {
            'Critical': '#dc3545',
            'High': '#fd7e14', 
            'Medium': '#ffc107',
            'Low': '#28a745'
        }
        
        vulnerability_cards = []
        for vuln_type, results in grouped_results.items():
            for result in results:
                severity_color = severity_colors.get(result.severity, '#6c757d')
                card = f"""
                <div class="vulnerability-card" style="border-left: 4px solid {severity_color};">
                    <div class="vuln-header">
                        <h4>{result.vulnerability_type.upper()}</h4>
                        <span class="severity-badge" style="background-color: {severity_color};">{result.severity}</span>
                    </div>
                    <div class="vuln-details">
                        <p><strong>URL:</strong> <a href="{result.url}" target="_blank">{result.url}</a></p>
                        <p><strong>Payload:</strong> <code>{result.payload}</code></p>
                        <p><strong>Evidence:</strong> <pre>{result.evidence}</pre></p>
                        <p><strong>Response Time:</strong> {result.response_time:.2f}s</p>
                        <p><strong>Status Code:</strong> {result.status_code}</p>
                        <p><strong>Timestamp:</strong> {result.timestamp}</p>
                    </div>
                </div>
                """
                vulnerability_cards.append(card)
        
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enhanced LOXS Security Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f8f9fa; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); overflow: hidden; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; padding: 30px; }}
        .stat-card {{ text-align: center; padding: 20px; background: #f8f9fa; border-radius: 10px; }}
        .stat-value {{ font-size: 2rem; font-weight: bold; color: #495057; }}
        .stat-label {{ color: #6c757d; margin-top: 5px; }}
        .content {{ padding: 30px; }}
        .vulnerability-card {{ background: white; border: 1px solid #dee2e6; border-radius: 8px; margin-bottom: 20px; padding: 20px; }}
        .vuln-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }}
        .vuln-header h4 {{ margin: 0; color: #495057; }}
        .severity-badge {{ color: white; padding: 4px 8px; border-radius: 4px; font-size: 0.8rem; }}
        .vuln-details p {{ margin: 8px 0; }}
        .vuln-details code {{ background: #f8f9fa; padding: 2px 4px; border-radius: 3px; }}
        .vuln-details pre {{ background: #f8f9fa; padding: 10px; border-radius: 5px; max-height: 150px; overflow-y: auto; }}
        h2 {{ color: #495057; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #dee2e6; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Enhanced LOXS Security Report</h1>
            <p>Automated Vulnerability Assessment</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">{len(self.results)}</div>
                <div class="stat-label">Vulnerabilities Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{self.stats['total_scanned']}</div>
                <div class="stat-label">URLs Scanned</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{scan_duration:.1f}s</div>
                <div class="stat-label">Scan Duration</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{len(grouped_results)}</div>
                <div class="stat-label">Vulnerability Types</div>
            </div>
        </div>
        
        <div class="content">
            <h2>🎯 Vulnerability Findings</h2>
            {' '.join(vulnerability_cards) if vulnerability_cards else '<p>No vulnerabilities found.</p>'}
        </div>
    </div>
</body>
</html>
        """

def main():
    """CLI interface for enhanced LOXS"""
    parser = argparse.ArgumentParser(description='Enhanced LOXS Vulnerability Scanner')
    parser.add_argument('-f', '--file', help='File containing URLs to scan')
    parser.add_argument('-u', '--url', help='Single URL to scan') 
    parser.add_argument('-g', '--gf-dir', help='Directory containing GF pattern results')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout')
    parser.add_argument('--scan-types', nargs='+', choices=['lfi', 'xss', 'sqli', 'or'], 
                       default=['lfi', 'xss', 'sqli', 'or'], help='Scan types')
    parser.add_argument('-o', '--output', help='Output report file')
    
    args = parser.parse_args()
    
    if not any([args.file, args.url, args.gf_dir]):
        print(f"{Colors.RED}Error: Must specify --file, --url, or --gf-dir{Colors.RESET}")
        return
    
    # Display banner
    banner = f"""
{Colors.CYAN}
╔══════════════════════════════════════════════════════╗
║                                                      ║
║           🎯 Enhanced LOXS Scanner 🎯                 ║
║                                                      ║
║    Automated Vulnerability Assessment Tool           ║
║                                                      ║
╚══════════════════════════════════════════════════════╝
{Colors.RESET}
    """
    print(banner)
    
    # Initialize scanner
    scanner = EnhancedLOXS(threads=args.threads, timeout=args.timeout)
    
    results = []
    
    # Scan from file
    if args.file:
        results.extend(scanner.scan_urls_from_file(args.file, args.scan_types))
    
    # Scan single URL
    if args.url:
        results.extend(scanner.scan_urls([args.url], args.scan_types))
    
    # Scan GF results
    if args.gf_dir:
        results.extend(scanner.scan_gf_patterns(args.gf_dir))
    
    # Generate report
    report_file = scanner.generate_report(args.output)
    
    # Display summary
    print(f"\n{Colors.GREEN}✅ Scan Complete!{Colors.RESET}")
    print(f"📊 Vulnerabilities Found: {Colors.RED}{len(results)}{Colors.RESET}")
    print(f"📁 Report Generated: {Colors.CYAN}{report_file}{Colors.RESET}")
    
    if results:
        print(f"\n{Colors.YELLOW}🎯 Vulnerability Summary:{Colors.RESET}")
        vuln_types = {}
        for result in results:
            vuln_types[result.vulnerability_type] = vuln_types.get(result.vulnerability_type, 0) + 1
        
        for vuln_type, count in vuln_types.items():
            print(f"   {vuln_type.upper()}: {count}")

if __name__ == "__main__":
    main()
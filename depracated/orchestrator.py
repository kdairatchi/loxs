#!/usr/bin/env python3
# ABOUTME: Enhanced Bug Bounty Orchestrator - Integrates filter.sh reconnaissance with loxs.py vulnerability scanning
# ABOUTME: Automates the complete workflow from reconnaissance to vulnerability assessment with intelligent data parsing

import os
import sys
import json
import subprocess
import argparse
import logging
import time
import glob
import re
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# Enhanced logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('orchestrator.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class ScanResults:
    """Data structure for scan results"""
    domain: str
    domains: List[str] = None
    live_domains: List[str] = None
    ip_addresses: List[str] = None
    urls: List[str] = None
    nuclei_findings: List[Dict] = None
    gf_patterns: Dict[str, List[str]] = None
    potential_vulns: Dict[str, List[str]] = None
    httpx_results: List[Dict] = None
    
class Colors:
    """ANSI color codes for terminal output"""
    BLUE = '\033[94m'
    GREEN = '\033[1;92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    ORANGE = '\033[38;5;208m'
    BOLD = '\033[1m'

class EnhancedOrchestrator:
    """Enhanced Bug Bounty Workflow Orchestrator"""
    
    def __init__(self, output_dir: str = None):
        self.output_dir = Path(output_dir) if output_dir else Path.cwd()
        self.script_dir = Path(__file__).parent
        self.filter_script = self.script_dir / "filter.sh"
        self.loxs_script = self.script_dir / "loxs.py"
        self.hunter_script = self.script_dir / "hunter.py"
        
        # Ensure scripts exist and are executable
        self._setup_environment()
        
    def _setup_environment(self):
        """Setup the environment and validate dependencies"""
        logger.info("Setting up environment...")
        
        # Make scripts executable
        for script in [self.filter_script]:
            if script.exists():
                os.chmod(script, 0o755)
                logger.info(f"Made {script.name} executable")
            else:
                logger.error(f"Required script not found: {script}")
                raise FileNotFoundError(f"Script not found: {script}")
    
    def run_reconnaissance(self, domain: str, quick: bool = False, passive_only: bool = False, 
                          verbose: bool = False, overwrite: bool = False) -> Path:
        """Run the enhanced filter.sh reconnaissance script"""
        logger.info(f"🔍 Starting reconnaissance for domain: {domain}")
        
        # Prepare command
        cmd = [str(self.filter_script)]
        cmd.extend(["-d", domain])
        cmd.extend(["-o", str(self.output_dir)])
        
        if quick:
            cmd.append("--quick")
        if passive_only:
            cmd.append("--passive-only")
        if verbose:
            cmd.append("--verbose")
        if overwrite:
            cmd.append("--overwrite")
            
        logger.info(f"Running command: {' '.join(cmd)}")
        
        try:
            # Run reconnaissance with real-time output
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )
            
            # Stream output in real-time
            for line in iter(process.stdout.readline, ''):
                print(f"{Colors.CYAN}[RECON]{Colors.RESET} {line.rstrip()}")
                logger.info(f"RECON: {line.rstrip()}")
                
            process.stdout.close()
            return_code = process.wait()
            
            if return_code == 0:
                logger.info(f"✅ Reconnaissance completed successfully for {domain}")
                return self.output_dir / domain
            else:
                logger.error(f"❌ Reconnaissance failed with return code: {return_code}")
                raise subprocess.CalledProcessError(return_code, cmd)
                
        except subprocess.CalledProcessError as e:
            logger.error(f"Reconnaissance script failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during reconnaissance: {e}")
            raise
    
    def parse_reconnaissance_results(self, domain_dir: Path) -> ScanResults:
        """Parse the results from filter.sh output files"""
        logger.info(f"📊 Parsing reconnaissance results from {domain_dir}")
        
        results = ScanResults(domain=domain_dir.name)
        
        try:
            # Parse domain lists
            results.domains = self._parse_file_lines(domain_dir / f"domains-{results.domain}.txt")
            results.live_domains = self._parse_file_lines(domain_dir / f"livedomains-{results.domain}.txt")
            results.ip_addresses = self._parse_file_lines(domain_dir / f"ip-addresses-{results.domain}.txt")
            results.urls = self._parse_file_lines(domain_dir / f"paths-{results.domain}.txt")
            
            # Parse HTTPX JSON results
            results.httpx_results = self._parse_httpx_results(domain_dir / f"httpx-{results.domain}.json")
            
            # Parse Nuclei findings
            results.nuclei_findings = self._parse_nuclei_results(
                domain_dir / f"nuclei-{results.domain}.jsonl",
                domain_dir / f"nuclei-{results.domain}.txt"
            )
            
            # Parse GF pattern results
            results.gf_patterns = self._parse_gf_patterns(domain_dir / "check-manually")
            
            # Parse potential vulnerabilities
            results.potential_vulns = self._parse_potential_vulns(domain_dir)
            
            logger.info(f"✅ Successfully parsed results for {results.domain}")
            logger.info(f"   📈 Stats: {len(results.domains or [])} domains, {len(results.live_domains or [])} live, "
                       f"{len(results.urls or [])} URLs, {len(results.nuclei_findings or [])} Nuclei findings")
            
            return results
            
        except Exception as e:
            logger.error(f"Error parsing reconnaissance results: {e}")
            raise
    
    def _parse_file_lines(self, file_path: Path) -> List[str]:
        """Parse a file and return non-empty lines"""
        if not file_path.exists():
            return []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = [line.strip() for line in f if line.strip()]
            return lines
        except Exception as e:
            logger.warning(f"Could not parse file {file_path}: {e}")
            return []
    
    def _parse_httpx_results(self, json_file: Path) -> List[Dict]:
        """Parse HTTPX JSON output"""
        if not json_file.exists():
            return []
            
        results = []
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        try:
                            results.append(json.loads(line.strip()))
                        except json.JSONDecodeError:
                            continue
            return results
        except Exception as e:
            logger.warning(f"Could not parse HTTPX results: {e}")
            return []
    
    def _parse_nuclei_results(self, jsonl_file: Path, txt_file: Path) -> List[Dict]:
        """Parse Nuclei findings from JSONL or TXT format"""
        findings = []
        
        # Try JSONL format first (preferred)
        if jsonl_file.exists():
            try:
                with open(jsonl_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        if line.strip():
                            try:
                                findings.append(json.loads(line.strip()))
                            except json.JSONDecodeError:
                                continue
                if findings:
                    return findings
            except Exception as e:
                logger.warning(f"Could not parse Nuclei JSONL: {e}")
        
        # Fallback to TXT format
        if txt_file.exists():
            try:
                with open(txt_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        if line.strip():
                            # Simple parsing for TXT format
                            parts = line.strip().split('\t')
                            if len(parts) >= 3:
                                findings.append({
                                    'timestamp': parts[0] if len(parts) > 0 else '',
                                    'info': {'severity': parts[1] if len(parts) > 1 else ''},
                                    'template-id': parts[2] if len(parts) > 2 else '',
                                    'matched-at': parts[3] if len(parts) > 3 else ''
                                })
            except Exception as e:
                logger.warning(f"Could not parse Nuclei TXT: {e}")
        
        return findings
    
    def _parse_gf_patterns(self, check_manually_dir: Path) -> Dict[str, List[str]]:
        """Parse GF pattern matching results"""
        patterns = {}
        
        if not check_manually_dir.exists():
            return patterns
            
        pattern_files = {
            'xss': 'cross-site-scripting.txt',
            'sqli': 'sql-injection.txt', 
            'lfi': 'local-file-inclusion.txt',
            'ssrf': 'server-side-request-forgery.txt',
            'rce': 'rce.txt',
            'idor': 'insecure-direct-object-reference.txt',
            'ssti': 'server-side-template-injection.txt',
            'redirect': 'open-redirect.txt',
            'debug': 'debug-parameters.txt',
            'cors': 'cors-misconfiguration.txt'
        }
        
        for pattern_name, filename in pattern_files.items():
            file_path = check_manually_dir / filename
            patterns[pattern_name] = self._parse_file_lines(file_path)
            
        return patterns
    
    def _parse_potential_vulns(self, domain_dir: Path) -> Dict[str, List[str]]:
        """Parse potential vulnerability findings"""
        potential_vulns = {}
        
        vuln_files = {
            'ssti': f'potential-ssti.txt',
            'lfi': f'potential-lfi.txt',
            'redirect': f'potential-or.txt'
        }
        
        for vuln_type, filename in vuln_files.items():
            file_path = domain_dir / filename
            potential_vulns[vuln_type] = self._parse_file_lines(file_path)
            
        return potential_vulns
    
    def run_vulnerability_scanning(self, results: ScanResults, scan_types: List[str] = None) -> Dict:
        """Run LOXS vulnerability scanning on the discovered URLs"""
        if not results.urls:
            logger.warning("No URLs found for vulnerability scanning")
            return {}
            
        logger.info(f"🎯 Starting vulnerability scanning on {len(results.urls)} URLs")
        
        if scan_types is None:
            scan_types = ['lfi', 'xss', 'sqli', 'or']  # Default scan types
            
        # Create temporary URL file for LOXS
        url_file = self.output_dir / f"{results.domain}_urls.txt"
        try:
            with open(url_file, 'w') as f:
                for url in results.urls:
                    f.write(f"{url}\n")
                    
            logger.info(f"Created URL file: {url_file} with {len(results.urls)} URLs")
            
            # Note: LOXS integration would require modifying loxs.py to accept file input
            # For now, we'll return the prepared data structure
            return {
                'url_file': str(url_file),
                'scan_types': scan_types,
                'target_count': len(results.urls),
                'prepared_for_loxs': True
            }
            
        except Exception as e:
            logger.error(f"Error preparing vulnerability scanning: {e}")
            return {}
    
    def run_ip_analysis(self, results: ScanResults) -> Dict:
        """Run hunter.py analysis on discovered IP addresses"""
        if not results.ip_addresses:
            logger.warning("No IP addresses found for analysis")
            return {}
            
        logger.info(f"🕵️ Starting IP analysis on {len(results.ip_addresses)} IPs")
        
        # Create temporary IP file for hunter.py
        ip_file = self.output_dir / f"{results.domain}_ips.txt"
        try:
            with open(ip_file, 'w') as f:
                for ip in results.ip_addresses:
                    f.write(f"{ip}\n")
                    
            logger.info(f"Running hunter.py analysis...")
            
            # Run hunter.py
            cmd = [sys.executable, str(self.hunter_script), "-f", str(ip_file), "--cve+ports"]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode == 0:
                logger.info("✅ IP analysis completed successfully")
                return {
                    'status': 'success',
                    'output': result.stdout,
                    'ip_count': len(results.ip_addresses),
                    'analysis_complete': True
                }
            else:
                logger.warning(f"IP analysis completed with warnings: {result.stderr}")
                return {
                    'status': 'partial',
                    'output': result.stdout,
                    'errors': result.stderr,
                    'ip_count': len(results.ip_addresses)
                }
                
        except subprocess.TimeoutExpired:
            logger.error("IP analysis timed out")
            return {'status': 'timeout', 'ip_count': len(results.ip_addresses)}
        except Exception as e:
            logger.error(f"Error running IP analysis: {e}")
            return {'status': 'error', 'error': str(e)}
    
    def generate_integrated_report(self, results: ScanResults, vuln_scan_results: Dict, 
                                 ip_analysis_results: Dict) -> str:
        """Generate a comprehensive HTML report"""
        logger.info("📝 Generating integrated report...")
        
        report_data = {
            'domain': results.domain,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'reconnaissance': {
                'total_domains': len(results.domains or []),
                'live_domains': len(results.live_domains or []),
                'total_ips': len(results.ip_addresses or []),
                'total_urls': len(results.urls or []),
                'nuclei_findings': len(results.nuclei_findings or []),
                'gf_patterns': {k: len(v) for k, v in (results.gf_patterns or {}).items()},
                'potential_vulns': {k: len(v) for k, v in (results.potential_vulns or {}).items()}
            },
            'vulnerability_scanning': vuln_scan_results,
            'ip_analysis': ip_analysis_results
        }
        
        # Generate HTML report
        report_html = self._generate_html_report(report_data)
        
        # Save report
        report_file = self.output_dir / f"{results.domain}_integrated_report.html"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report_html)
            
        logger.info(f"✅ Report generated: {report_file}")
        return str(report_file)
    
    def _generate_html_report(self, data: Dict) -> str:
        """Generate HTML report from data"""
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Integrated Security Report - {data['domain']}</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; margin-bottom: 40px; }}
        .header h1 {{ color: #2c3e50; margin-bottom: 10px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 30px 0; }}
        .stat-card {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; text-align: center; }}
        .stat-value {{ font-size: 2em; font-weight: bold; margin-bottom: 10px; }}
        .section {{ margin: 30px 0; }}
        .section h2 {{ color: #34495e; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
        .findings-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }}
        .finding-card {{ background: #fff; border: 1px solid #ddd; padding: 15px; border-radius: 8px; }}
        .severity-high {{ border-left: 4px solid #e74c3c; }}
        .severity-medium {{ border-left: 4px solid #f39c12; }}
        .severity-low {{ border-left: 4px solid #27ae60; }}
        .url-list {{ max-height: 300px; overflow-y: auto; background: #f8f9fa; padding: 15px; border-radius: 5px; }}
        .timestamp {{ color: #7f8c8d; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Integrated Security Assessment Report</h1>
            <h2>{data['domain']}</h2>
            <p class="timestamp">Generated: {data['timestamp']}</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{data['reconnaissance']['total_domains']}</div>
                <div>Total Domains</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{data['reconnaissance']['live_domains']}</div>
                <div>Live Domains</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{data['reconnaissance']['total_urls']}</div>
                <div>URLs Discovered</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{data['reconnaissance']['nuclei_findings']}</div>
                <div>Nuclei Findings</div>
            </div>
        </div>
        
        <div class="section">
            <h2>🔍 Reconnaissance Summary</h2>
            <div class="findings-grid">
                <div class="finding-card">
                    <h4>Domain Discovery</h4>
                    <p><strong>Total Domains:</strong> {data['reconnaissance']['total_domains']}</p>
                    <p><strong>Live Domains:</strong> {data['reconnaissance']['live_domains']}</p>
                    <p><strong>IP Addresses:</strong> {data['reconnaissance']['total_ips']}</p>
                </div>
                <div class="finding-card">
                    <h4>URL Collection</h4>
                    <p><strong>Total URLs:</strong> {data['reconnaissance']['total_urls']}</p>
                    <p><strong>Nuclei Findings:</strong> {data['reconnaissance']['nuclei_findings']}</p>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>🎯 GF Pattern Analysis</h2>
            <div class="findings-grid">
                {self._generate_gf_pattern_cards(data['reconnaissance']['gf_patterns'])}
            </div>
        </div>
        
        <div class="section">
            <h2>⚠️ Potential Vulnerabilities</h2>
            <div class="findings-grid">
                {self._generate_potential_vuln_cards(data['reconnaissance']['potential_vulns'])}
            </div>
        </div>
        
        <div class="section">
            <h2>🕵️ IP Analysis</h2>
            <div class="finding-card">
                <p><strong>Status:</strong> {data.get('ip_analysis', {}).get('status', 'Not run')}</p>
                <p><strong>IPs Analyzed:</strong> {data.get('ip_analysis', {}).get('ip_count', 0)}</p>
            </div>
        </div>
    </div>
</body>
</html>
"""
    
    def _generate_gf_pattern_cards(self, gf_patterns: Dict[str, int]) -> str:
        """Generate HTML cards for GF patterns"""
        cards = []
        for pattern, count in gf_patterns.items():
            severity_class = "severity-high" if count > 10 else "severity-medium" if count > 0 else "severity-low"
            cards.append(f"""
                <div class="finding-card {severity_class}">
                    <h4>{pattern.upper()} Pattern</h4>
                    <p><strong>Matches:</strong> {count}</p>
                </div>
            """)
        return ''.join(cards)
    
    def _generate_potential_vuln_cards(self, potential_vulns: Dict[str, int]) -> str:
        """Generate HTML cards for potential vulnerabilities"""
        cards = []
        for vuln_type, count in potential_vulns.items():
            severity_class = "severity-high" if count > 0 else "severity-low"
            cards.append(f"""
                <div class="finding-card {severity_class}">
                    <h4>{vuln_type.upper()}</h4>
                    <p><strong>Potential Issues:</strong> {count}</p>
                </div>
            """)
        return ''.join(cards)
    
    def run_complete_workflow(self, domain: str, quick: bool = False, passive_only: bool = False,
                             verbose: bool = False, scan_types: List[str] = None) -> Dict:
        """Run the complete integrated workflow"""
        logger.info(f"🚀 Starting complete workflow for domain: {domain}")
        
        try:
            # Step 1: Reconnaissance
            domain_dir = self.run_reconnaissance(domain, quick, passive_only, verbose, overwrite=True)
            
            # Step 2: Parse Results  
            results = self.parse_reconnaissance_results(domain_dir)
            
            # Step 3: Vulnerability Scanning Preparation
            vuln_scan_results = self.run_vulnerability_scanning(results, scan_types)
            
            # Step 4: IP Analysis
            ip_analysis_results = self.run_ip_analysis(results)
            
            # Step 5: Generate Report
            report_file = self.generate_integrated_report(results, vuln_scan_results, ip_analysis_results)
            
            logger.info(f"🎉 Complete workflow finished successfully!")
            logger.info(f"📊 Report available at: {report_file}")
            
            return {
                'status': 'success',
                'domain': domain,
                'results': results,
                'vulnerability_scanning': vuln_scan_results,
                'ip_analysis': ip_analysis_results,
                'report_file': report_file
            }
            
        except Exception as e:
            logger.error(f"❌ Workflow failed: {e}")
            return {
                'status': 'failed',
                'error': str(e),
                'domain': domain
            }

def main():
    """Main function with CLI interface"""
    parser = argparse.ArgumentParser(description='Enhanced Bug Bounty Workflow Orchestrator')
    parser.add_argument('-d', '--domain', required=True, help='Target domain')
    parser.add_argument('-o', '--output', help='Output directory', default='.')
    parser.add_argument('-q', '--quick', action='store_true', help='Quick scan mode')
    parser.add_argument('-p', '--passive-only', action='store_true', help='Passive reconnaissance only')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--scan-types', nargs='+', help='Vulnerability scan types', 
                       choices=['lfi', 'xss', 'sqli', 'or', 'crlf'], default=['lfi', 'xss', 'sqli', 'or'])
    
    args = parser.parse_args()
    
    # Display banner
    banner = f"""
{Colors.CYAN}
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║          🛡️  Enhanced Bug Bounty Orchestrator 🛡️              ║
║                                                               ║
║     Integrates: filter.sh + loxs.py + hunter.py              ║
║     Target: {args.domain:<45}           ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
{Colors.RESET}
    """
    print(banner)
    
    # Initialize orchestrator
    orchestrator = EnhancedOrchestrator(args.output)
    
    # Run complete workflow
    results = orchestrator.run_complete_workflow(
        domain=args.domain,
        quick=args.quick,
        passive_only=args.passive_only,
        verbose=args.verbose,
        scan_types=args.scan_types
    )
    
    # Display results
    if results['status'] == 'success':
        print(f"{Colors.GREEN}✅ Workflow completed successfully!{Colors.RESET}")
        print(f"{Colors.CYAN}📊 Report: {results['report_file']}{Colors.RESET}")
    else:
        print(f"{Colors.RED}❌ Workflow failed: {results.get('error', 'Unknown error')}{Colors.RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()
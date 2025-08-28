#!/usr/bin/env python3
# ABOUTME: LOXS Integration Layer - Automatically processes filter.sh outputs and feeds them into original loxs.py
# ABOUTME: Handles large files efficiently using sampling and creates automated vulnerability scanning workflow

import os
import sys
import subprocess
import json
import random
from pathlib import Path
import time
from datetime import datetime

class Colors:
    GREEN = '\033[1;92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class LOXSIntegration:
    """Integration layer between filter.sh and loxs.py"""
    
    def __init__(self, domain_dir: str):
        self.domain_dir = Path(domain_dir)
        self.domain = self.domain_dir.name
        self.script_dir = Path(__file__).parent
        
    def extract_urls_efficiently(self, max_urls: int = 1000) -> str:
        """Efficiently extract URLs from filter.sh outputs using head/tail sampling"""
        print(f"{Colors.CYAN}[INFO]{Colors.RESET} Extracting URLs from reconnaissance data...")
        
        url_files = [
            f"paths-{self.domain}.txt",
            f"WayBack-{self.domain}.txt"
        ]
        
        all_urls = set()
        
        for filename in url_files:
            file_path = self.domain_dir / filename
            if file_path.exists():
                # Get file size info
                line_count = int(subprocess.run(['wc', '-l', str(file_path)], 
                                              capture_output=True, text=True).stdout.split()[0])
                
                if line_count > max_urls:
                    print(f"{Colors.YELLOW}[INFO]{Colors.RESET} {filename} has {line_count} lines, sampling efficiently...")
                    
                    # Sample from head, middle, and tail
                    head_lines = int(max_urls * 0.4)  # 40% from beginning
                    tail_lines = int(max_urls * 0.4)  # 40% from end
                    middle_lines = max_urls - head_lines - tail_lines  # 20% from middle
                    
                    # Get head
                    head_result = subprocess.run(['head', '-n', str(head_lines), str(file_path)], 
                                               capture_output=True, text=True)
                    all_urls.update(head_result.stdout.strip().split('\n'))
                    
                    # Get tail
                    tail_result = subprocess.run(['tail', '-n', str(tail_lines), str(file_path)], 
                                               capture_output=True, text=True)
                    all_urls.update(tail_result.stdout.strip().split('\n'))
                    
                    # Get random middle section
                    if middle_lines > 0:
                        skip_lines = max(1, line_count // 2 - middle_lines // 2)
                        middle_result = subprocess.run(['sed', '-n', f'{skip_lines},{skip_lines + middle_lines}p', str(file_path)], 
                                                     capture_output=True, text=True)
                        all_urls.update(middle_result.stdout.strip().split('\n'))
                else:
                    # File is small enough, read all
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        all_urls.update(line.strip() for line in f if line.strip())
        
        # Filter and clean URLs
        valid_urls = []
        for url in all_urls:
            if url and url.startswith(('http://', 'https://')) and '?' in url:
                valid_urls.append(url)
        
        # Create URL file for LOXS
        url_file = self.domain_dir / f"loxs_urls_{self.domain}.txt"
        with open(url_file, 'w') as f:
            for url in valid_urls[:max_urls]:  # Limit final count
                f.write(f"{url}\n")
        
        print(f"{Colors.GREEN}[SUCCESS]{Colors.RESET} Extracted {len(valid_urls)} URLs to {url_file}")
        return str(url_file)
    
    def extract_gf_patterns(self) -> dict:
        """Extract URLs from GF pattern matching results"""
        print(f"{Colors.CYAN}[INFO]{Colors.RESET} Processing GF pattern results...")
        
        gf_dir = self.domain_dir / "check-manually"
        if not gf_dir.exists():
            return {}
        
        pattern_files = {
            'lfi': 'local-file-inclusion.txt',
            'xss': 'cross-site-scripting.txt', 
            'sqli': 'sql-injection.txt',
            'or': 'open-redirect.txt'
        }
        
        pattern_urls = {}
        
        for vuln_type, filename in pattern_files.items():
            file_path = gf_dir / filename
            if file_path.exists():
                # Get first 200 lines efficiently
                result = subprocess.run(['head', '-n', '200', str(file_path)], 
                                      capture_output=True, text=True)
                urls = [line.strip() for line in result.stdout.split('\n') if line.strip()]
                pattern_urls[vuln_type] = urls
                
                # Save individual pattern files for LOXS
                pattern_file = self.domain_dir / f"loxs_{vuln_type}_{self.domain}.txt"
                with open(pattern_file, 'w') as f:
                    for url in urls:
                        f.write(f"{url}\n")
                        
                print(f"{Colors.GREEN}[PATTERN]{Colors.RESET} {vuln_type.upper()}: {len(urls)} URLs")
        
        return pattern_urls
    
    def run_loxs_automated(self, url_file: str, scan_types: list = None):
        """Run original LOXS with automated input"""
        if scan_types is None:
            scan_types = ['1', '2', '3', '4']  # LFI, OR, SQLi, XSS
            
        print(f"{Colors.BOLD}{Colors.CYAN}[LOXS]{Colors.RESET} Starting automated vulnerability scanning...")
        
        # Prepare automated responses for LOXS interactive prompts
        loxs_script = self.script_dir / "loxs.py"
        
        for scan_type in scan_types:
            scan_names = {'1': 'LFI', '2': 'OR', '3': 'SQLi', '4': 'XSS'}
            print(f"{Colors.YELLOW}[SCAN]{Colors.RESET} Running {scan_names.get(scan_type, scan_type)} scan...")
            
            try:
                # Create input sequence for LOXS
                input_sequence = f"{scan_type}\n{url_file}\n2\ny\n7\n"  # scan_type, file, threads=2, save results, exit
                
                # Run LOXS with automated input
                process = subprocess.Popen(
                    [sys.executable, str(loxs_script)],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    cwd=str(self.script_dir)
                )
                
                stdout, stderr = process.communicate(input=input_sequence, timeout=300)
                
                if "vulnerable" in stdout.lower():
                    print(f"{Colors.RED}[VULN FOUND]{Colors.RESET} {scan_names.get(scan_type)} vulnerabilities detected!")
                else:
                    print(f"{Colors.GREEN}[CLEAN]{Colors.RESET} No {scan_names.get(scan_type)} vulnerabilities found")
                    
            except subprocess.TimeoutExpired:
                print(f"{Colors.YELLOW}[TIMEOUT]{Colors.RESET} {scan_names.get(scan_type)} scan timed out")
                process.kill()
            except Exception as e:
                print(f"{Colors.RED}[ERROR]{Colors.RESET} {scan_names.get(scan_type)} scan failed: {e}")
    
    def extract_ip_addresses(self) -> str:
        """Extract IP addresses for hunter.py"""
        ip_file = self.domain_dir / f"ip-addresses-{self.domain}.txt"
        if ip_file.exists():
            # Sample IPs efficiently for large files
            line_count = int(subprocess.run(['wc', '-l', str(ip_file)], 
                                          capture_output=True, text=True).stdout.split()[0])
            
            if line_count > 100:
                # Sample first 50 and last 50
                head_result = subprocess.run(['head', '-n', '50', str(ip_file)], 
                                           capture_output=True, text=True)
                tail_result = subprocess.run(['tail', '-n', '50', str(ip_file)], 
                                           capture_output=True, text=True)
                
                sampled_ips = set()
                sampled_ips.update(head_result.stdout.strip().split('\n'))
                sampled_ips.update(tail_result.stdout.strip().split('\n'))
                
                # Create sampled file
                sampled_file = self.domain_dir / f"sampled_ips_{self.domain}.txt"
                with open(sampled_file, 'w') as f:
                    for ip in sampled_ips:
                        if ip.strip():
                            f.write(f"{ip.strip()}\n")
                
                print(f"{Colors.CYAN}[INFO]{Colors.RESET} Sampled {len(sampled_ips)} IPs from {line_count} total")
                return str(sampled_file)
            else:
                return str(ip_file)
        
        return ""
    
    def run_hunter_analysis(self, ip_file: str):
        """Run enhanced hunter analysis"""
        if not ip_file or not Path(ip_file).exists():
            print(f"{Colors.YELLOW}[INFO]{Colors.RESET} No IP addresses to analyze")
            return
            
        print(f"{Colors.CYAN}[HUNTER]{Colors.RESET} Starting IP reconnaissance...")
        
        hunter_script = self.script_dir / "hunter_enhanced.py"
        if not hunter_script.exists():
            hunter_script = self.script_dir / "hunter.py"  # Fallback to original
        
        try:
            cmd = [sys.executable, str(hunter_script), "-f", ip_file, "--cve+ports", "--quiet"]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            
            if result.returncode == 0:
                print(f"{Colors.GREEN}[SUCCESS]{Colors.RESET} IP analysis completed")
                
                # Extract key findings from output
                if "CRITICAL" in result.stdout:
                    print(f"{Colors.RED}[CRITICAL]{Colors.RESET} Critical CVEs found!")
                if "HIGH" in result.stdout:
                    print(f"{Colors.YELLOW}[HIGH]{Colors.RESET} High-risk CVEs detected!")
                    
            else:
                print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} Hunter completed with warnings")
                
        except subprocess.TimeoutExpired:
            print(f"{Colors.YELLOW}[TIMEOUT]{Colors.RESET} IP analysis timed out")
        except Exception as e:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Hunter analysis failed: {e}")
    
    def generate_integration_report(self):
        """Generate a summary report of the integration"""
        report_file = self.domain_dir / f"integration_report_{self.domain}.txt"
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open(report_file, 'w') as f:
            f.write(f"LOXS Integration Report - {self.domain}\n")
            f.write(f"Generated: {timestamp}\n")
            f.write("=" * 50 + "\n\n")
            
            # Check what files exist
            files_found = []
            expected_files = [
                f"domains-{self.domain}.txt",
                f"livedomains-{self.domain}.txt", 
                f"paths-{self.domain}.txt",
                f"ip-addresses-{self.domain}.txt",
                f"nuclei-{self.domain}.txt",
                "check-manually/"
            ]
            
            for filename in expected_files:
                file_path = self.domain_dir / filename
                if file_path.exists():
                    if file_path.is_dir():
                        file_count = len(list(file_path.glob("*.txt")))
                        files_found.append(f"{filename}: {file_count} pattern files")
                    else:
                        line_count = int(subprocess.run(['wc', '-l', str(file_path)], 
                                                      capture_output=True, text=True).stdout.split()[0])
                        files_found.append(f"{filename}: {line_count} lines")
            
            f.write("Files processed:\n")
            for file_info in files_found:
                f.write(f"  ✓ {file_info}\n")
            
            f.write(f"\nIntegration completed successfully!\n")
        
        print(f"{Colors.GREEN}[REPORT]{Colors.RESET} Integration report saved to {report_file}")

def main():
    """Main automation workflow"""
    import argparse
    
    parser = argparse.ArgumentParser(description='LOXS Integration - Automate filter.sh → loxs.py workflow')
    parser.add_argument('-d', '--domain-dir', required=True, help='Domain directory from filter.sh output')
    parser.add_argument('--max-urls', type=int, default=1000, help='Maximum URLs to process (default: 1000)')
    parser.add_argument('--skip-loxs', action='store_true', help='Skip LOXS vulnerability scanning')
    parser.add_argument('--skip-hunter', action='store_true', help='Skip Hunter IP analysis')
    parser.add_argument('--scan-types', nargs='+', choices=['1', '2', '3', '4'], 
                       default=['1', '2', '3', '4'], help='LOXS scan types (1=LFI, 2=OR, 3=SQLi, 4=XSS)')
    
    args = parser.parse_args()
    
    if not Path(args.domain_dir).exists():
        print(f"{Colors.RED}[ERROR]{Colors.RESET} Domain directory not found: {args.domain_dir}")
        return
    
    # Banner
    print(f"""
{Colors.CYAN}{Colors.BOLD}
╔════════════════════════════════════════════════════════╗
║                                                        ║
║         🔗 LOXS Integration Automation 🔗              ║
║                                                        ║
║    filter.sh → loxs.py → hunter.py (Automated)        ║
║                                                        ║
╚════════════════════════════════════════════════════════╝
{Colors.RESET}
    """)
    
    # Initialize integration
    integration = LOXSIntegration(args.domain_dir)
    
    print(f"{Colors.CYAN}[START]{Colors.RESET} Processing domain: {integration.domain}")
    
    try:
        # Step 1: Extract URLs efficiently
        url_file = integration.extract_urls_efficiently(args.max_urls)
        
        # Step 2: Process GF patterns
        gf_patterns = integration.extract_gf_patterns()
        
        # Step 3: Run LOXS vulnerability scanning
        if not args.skip_loxs:
            integration.run_loxs_automated(url_file, args.scan_types)
        
        # Step 4: Extract and analyze IPs
        if not args.skip_hunter:
            ip_file = integration.extract_ip_addresses()
            integration.run_hunter_analysis(ip_file)
        
        # Step 5: Generate summary report
        integration.generate_integration_report()
        
        print(f"\n{Colors.GREEN}{Colors.BOLD}[COMPLETE]{Colors.RESET} Integration workflow finished!")
        print(f"{Colors.CYAN}[INFO]{Colors.RESET} Check {integration.domain_dir} for results")
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[INTERRUPTED]{Colors.RESET} Workflow stopped by user")
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.RESET} Workflow failed: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
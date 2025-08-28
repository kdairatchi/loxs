#!/usr/bin/env python3
# ABOUTME: Master Automation Script - Complete workflow from reconnaissance to vulnerability assessment
# ABOUTME: Orchestrates filter.sh -> loxs.py -> hunter.py with intelligent data flow and efficient processing

import os
import sys
import subprocess
import time
from pathlib import Path
from datetime import datetime
import argparse
import json

class Colors:
    GREEN = '\033[1;92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    PURPLE = '\033[95m'

class MasterAutomation:
    """Master automation orchestrator"""
    
    def __init__(self, output_dir: str = "scan_results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.script_dir = Path(__file__).parent
        
        # Scripts
        self.filter_script = self.script_dir / "filter.sh"
        self.integration_script = self.script_dir / "loxs_integration.py"
        self.wrapper_script = self.script_dir / "loxs_wrapper.py"
        self.hunter_script = self.script_dir / "hunter_enhanced.py"
        
        self._make_executable()
    
    def _make_executable(self):
        """Make all scripts executable"""
        scripts = [self.filter_script, self.integration_script, self.wrapper_script, self.hunter_script]
        for script in scripts:
            if script.exists():
                os.chmod(script, 0o755)
    
    def run_reconnaissance(self, domain: str, quick: bool = False, passive: bool = False, verbose: bool = False):
        """Step 1: Run filter.sh reconnaissance"""
        print(f"\n{Colors.PURPLE}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}STEP 1: RECONNAISSANCE - {domain.upper()}{Colors.RESET}")
        print(f"{Colors.PURPLE}{'='*60}{Colors.RESET}")
        
        domain_output = self.output_dir / domain
        
        cmd = [str(self.filter_script), "-d", domain, "-o", str(self.output_dir)]
        if quick:
            cmd.append("--quick")
        if passive:
            cmd.append("--passive-only")
        if verbose:
            cmd.append("--verbose")
        cmd.append("--overwrite")  # Always overwrite for automation
        
        print(f"{Colors.CYAN}[CMD]{Colors.RESET} {' '.join(cmd)}")
        
        try:
            # Stream output in real-time
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                                     universal_newlines=True, bufsize=1)
            
            recon_success = True
            for line in iter(process.stdout.readline, ''):
                line = line.rstrip()
                if line:
                    print(f"{Colors.CYAN}[RECON]{Colors.RESET} {line}")
                    if "error" in line.lower() or "failed" in line.lower():
                        recon_success = False
            
            process.stdout.close()
            return_code = process.wait()
            
            if return_code == 0 and recon_success:
                print(f"{Colors.GREEN}[SUCCESS]{Colors.RESET} Reconnaissance completed")
                return domain_output
            else:
                print(f"{Colors.RED}[ERROR]{Colors.RESET} Reconnaissance failed")
                return None
                
        except Exception as e:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Reconnaissance error: {e}")
            return None
    
    def run_vulnerability_scanning(self, domain_dir: Path, scan_types: list = None, max_urls: int = 1000):
        """Step 2: Run LOXS vulnerability scanning"""
        print(f"\n{Colors.PURPLE}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}STEP 2: VULNERABILITY SCANNING{Colors.RESET}")
        print(f"{Colors.PURPLE}{'='*60}{Colors.RESET}")
        
        if scan_types is None:
            scan_types = ['1', '2', '3', '4']  # LFI, OR, SQLi, XSS
        
        try:
            # Use integration script to prepare and run LOXS
            cmd = [
                sys.executable, str(self.integration_script),
                "-d", str(domain_dir),
                "--max-urls", str(max_urls),
                "--scan-types"] + scan_types
            
            print(f"{Colors.CYAN}[CMD]{Colors.RESET} {' '.join(cmd)}")
            
            result = subprocess.run(cmd, capture_output=False, text=True, timeout=600)
            
            if result.returncode == 0:
                print(f"{Colors.GREEN}[SUCCESS]{Colors.RESET} Vulnerability scanning completed")
                return True
            else:
                print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} Vulnerability scanning completed with warnings")
                return True
                
        except subprocess.TimeoutExpired:
            print(f"{Colors.YELLOW}[TIMEOUT]{Colors.RESET} Vulnerability scanning timed out")
            return False
        except Exception as e:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Vulnerability scanning error: {e}")
            return False
    
    def run_ip_analysis(self, domain_dir: Path):
        """Step 3: Run IP analysis with hunter"""
        print(f"\n{Colors.PURPLE}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}STEP 3: IP RECONNAISSANCE{Colors.RESET}")
        print(f"{Colors.PURPLE}{'='*60}{Colors.RESET}")
        
        domain = domain_dir.name
        ip_file = domain_dir / f"ip-addresses-{domain}.txt"
        
        if not ip_file.exists():
            print(f"{Colors.YELLOW}[SKIP]{Colors.RESET} No IP addresses found")
            return True
        
        # Check file size and sample if needed
        try:
            line_count = int(subprocess.run(['wc', '-l', str(ip_file)], 
                                          capture_output=True, text=True).stdout.split()[0])
            
            if line_count == 0:
                print(f"{Colors.YELLOW}[SKIP]{Colors.RESET} IP file is empty")
                return True
                
            # Sample large files
            working_file = ip_file
            if line_count > 50:
                print(f"{Colors.CYAN}[INFO]{Colors.RESET} Sampling {line_count} IPs -> 50 for analysis")
                sampled_file = domain_dir / f"sampled_ips_{domain}.txt"
                
                # Get head and tail
                subprocess.run(f"head -n 25 '{ip_file}' > '{sampled_file}'", shell=True)
                subprocess.run(f"tail -n 25 '{ip_file}' >> '{sampled_file}'", shell=True)
                working_file = sampled_file
            
            # Run hunter analysis
            cmd = [sys.executable, str(self.hunter_script), "-f", str(working_file), 
                   "--cve+ports", "--json-output", str(domain_dir / f"hunter_results_{domain}.json")]
            
            print(f"{Colors.CYAN}[CMD]{Colors.RESET} {' '.join(cmd)}")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                print(f"{Colors.GREEN}[SUCCESS]{Colors.RESET} IP analysis completed")
                
                # Parse key findings from output
                output = result.stdout
                if "CRITICAL" in output:
                    print(f"{Colors.RED}[ALERT]{Colors.RESET} Critical CVEs detected!")
                if "HIGH" in output:
                    print(f"{Colors.YELLOW}[ALERT]{Colors.RESET} High-risk CVEs found!")
                    
                return True
            else:
                print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} IP analysis completed with issues")
                return True
                
        except subprocess.TimeoutExpired:
            print(f"{Colors.YELLOW}[TIMEOUT]{Colors.RESET} IP analysis timed out")
            return False
        except Exception as e:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} IP analysis error: {e}")
            return False
    
    def generate_final_report(self, domain_dir: Path):
        """Step 4: Generate comprehensive final report"""
        print(f"\n{Colors.PURPLE}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}STEP 4: FINAL REPORT GENERATION{Colors.RESET}")
        print(f"{Colors.PURPLE}{'='*60}{Colors.RESET}")
        
        domain = domain_dir.name
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
        # Collect all results
        results = {
            'domain': domain,
            'timestamp': timestamp,
            'files_found': [],
            'statistics': {}
        }
        
        # Check what files exist and get basic stats
        files_to_check = [
            f"domains-{domain}.txt",
            f"livedomains-{domain}.txt",
            f"paths-{domain}.txt", 
            f"ip-addresses-{domain}.txt",
            f"nuclei-{domain}.txt",
            f"nuclei-{domain}.jsonl"
        ]
        
        for filename in files_to_check:
            file_path = domain_dir / filename
            if file_path.exists():
                try:
                    line_count = int(subprocess.run(['wc', '-l', str(file_path)], 
                                                  capture_output=True, text=True).stdout.split()[0])
                    results['files_found'].append(f"{filename}: {line_count} entries")
                    
                    # Extract key statistics
                    if "domains-" in filename:
                        results['statistics']['total_domains'] = line_count
                    elif "livedomains-" in filename:
                        results['statistics']['live_domains'] = line_count
                    elif "paths-" in filename:
                        results['statistics']['total_urls'] = line_count
                    elif "ip-addresses-" in filename:
                        results['statistics']['ip_addresses'] = line_count
                    elif "nuclei-" in filename and filename.endswith('.txt'):
                        results['statistics']['nuclei_findings'] = line_count
                        
                except:
                    results['files_found'].append(f"{filename}: found")
        
        # Check GF patterns
        gf_dir = domain_dir / "check-manually"
        if gf_dir.exists():
            pattern_files = list(gf_dir.glob("*.txt"))
            results['statistics']['gf_patterns'] = len(pattern_files)
            
            # Count total pattern matches
            total_patterns = 0
            for pf in pattern_files:
                try:
                    count = int(subprocess.run(['wc', '-l', str(pf)], 
                                             capture_output=True, text=True).stdout.split()[0])
                    total_patterns += count
                except:
                    pass
            results['statistics']['total_pattern_matches'] = total_patterns
        
        # Generate report
        report_file = domain_dir / f"FINAL_REPORT_{domain}_{timestamp}.txt"
        
        with open(report_file, 'w') as f:
            f.write(f"╔════════════════════════════════════════════════════════════╗\n")
            f.write(f"║              AUTOMATED SECURITY ASSESSMENT REPORT          ║\n")
            f.write(f"╚════════════════════════════════════════════════════════════╝\n\n")
            
            f.write(f"Domain: {domain}\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Automation: filter.sh → loxs.py → hunter.py\n")
            f.write(f"{'='*60}\n\n")
            
            f.write(f"STATISTICS:\n")
            f.write(f"{'─'*20}\n")
            for key, value in results['statistics'].items():
                f.write(f"{key.replace('_', ' ').title()}: {value}\n")
            
            f.write(f"\nFILES GENERATED:\n")
            f.write(f"{'─'*20}\n")
            for file_info in results['files_found']:
                f.write(f"✓ {file_info}\n")
            
            f.write(f"\nNEXT STEPS:\n")
            f.write(f"{'─'*20}\n")
            f.write(f"1. Review nuclei findings in nuclei-{domain}.txt\n")
            f.write(f"2. Check GF pattern results in check-manually/\n")
            f.write(f"3. Analyze LOXS vulnerability scan outputs\n")
            f.write(f"4. Review hunter IP analysis results\n")
            f.write(f"5. Investigate potential vulnerabilities manually\n")
            
            f.write(f"\n{'='*60}\n")
            f.write(f"Report generated by Enhanced LOXS Automation Suite\n")
        
        print(f"{Colors.GREEN}[REPORT]{Colors.RESET} Final report: {report_file}")
        return str(report_file)
    
    def run_complete_workflow(self, domain: str, quick: bool = False, passive: bool = False, 
                             verbose: bool = False, scan_types: list = None, max_urls: int = 1000):
        """Run the complete automated workflow"""
        start_time = time.time()
        
        print(f"""
{Colors.PURPLE}{Colors.BOLD}
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║        🚀 MASTER AUTOMATION WORKFLOW 🚀                    ║
║                                                            ║
║    Complete Bug Bounty Pipeline: Recon → Scan → Report    ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
{Colors.RESET}

{Colors.CYAN}Target Domain:{Colors.RESET} {domain}
{Colors.CYAN}Output Directory:{Colors.RESET} {self.output_dir}
{Colors.CYAN}Max URLs:{Colors.RESET} {max_urls}
{Colors.CYAN}Scan Types:{Colors.RESET} {scan_types or ['1', '2', '3', '4']}
        """)
        
        success_steps = []
        
        try:
            # Step 1: Reconnaissance
            domain_dir = self.run_reconnaissance(domain, quick, passive, verbose)
            if domain_dir:
                success_steps.append("Reconnaissance")
            else:
                print(f"{Colors.RED}[ABORT]{Colors.RESET} Reconnaissance failed - stopping workflow")
                return False
            
            # Step 2: Vulnerability Scanning
            if self.run_vulnerability_scanning(domain_dir, scan_types, max_urls):
                success_steps.append("Vulnerability Scanning")
            
            # Step 3: IP Analysis
            if self.run_ip_analysis(domain_dir):
                success_steps.append("IP Analysis")
            
            # Step 4: Final Report
            report_file = self.generate_final_report(domain_dir)
            if report_file:
                success_steps.append("Final Report")
            
            # Summary
            end_time = time.time()
            duration = end_time - start_time
            
            print(f"\n{Colors.PURPLE}{'='*60}{Colors.RESET}")
            print(f"{Colors.BOLD}🎉 WORKFLOW COMPLETED 🎉{Colors.RESET}")
            print(f"{Colors.PURPLE}{'='*60}{Colors.RESET}")
            print(f"{Colors.GREEN}✅ Completed Steps:{Colors.RESET} {', '.join(success_steps)}")
            print(f"{Colors.CYAN}⏱️ Total Duration:{Colors.RESET} {duration/60:.1f} minutes")
            print(f"{Colors.CYAN}📁 Results Directory:{Colors.RESET} {domain_dir}")
            print(f"{Colors.CYAN}📊 Final Report:{Colors.RESET} {report_file}")
            print(f"{Colors.PURPLE}{'='*60}{Colors.RESET}")
            
            return True
            
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[INTERRUPTED]{Colors.RESET} Workflow stopped by user")
            return False
        except Exception as e:
            print(f"\n{Colors.RED}[ERROR]{Colors.RESET} Workflow failed: {e}")
            return False

def main():
    """CLI interface for master automation"""
    parser = argparse.ArgumentParser(description='Master Security Automation - Complete Bug Bounty Pipeline')
    parser.add_argument('-d', '--domain', required=True, help='Target domain')
    parser.add_argument('-o', '--output', default='scan_results', help='Output directory')
    parser.add_argument('-q', '--quick', action='store_true', help='Quick reconnaissance mode')
    parser.add_argument('-p', '--passive', action='store_true', help='Passive reconnaissance only')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--max-urls', type=int, default=1000, help='Maximum URLs to process')
    parser.add_argument('--scan-types', nargs='+', choices=['1', '2', '3', '4', '5'], 
                       default=['1', '2', '3', '4'], help='LOXS scan types')
    
    args = parser.parse_args()
    
    # Initialize automation
    automation = MasterAutomation(args.output)
    
    # Run complete workflow
    success = automation.run_complete_workflow(
        domain=args.domain,
        quick=args.quick,
        passive=args.passive,
        verbose=args.verbose,
        scan_types=args.scan_types,
        max_urls=args.max_urls
    )
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
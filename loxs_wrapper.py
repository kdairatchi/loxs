#!/usr/bin/env python3
# ABOUTME: LOXS Wrapper - Automatically feeds URLs from filter.sh into original loxs.py with smart batching
# ABOUTME: Handles large URL lists efficiently and automates the interactive menu system of original loxs.py

import os
import sys
import subprocess
import time
import random
from pathlib import Path
import threading

class Colors:
    GREEN = '\033[1;92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class LoxsWrapper:
    """Smart wrapper for original loxs.py with file input automation"""
    
    def __init__(self):
        self.script_dir = Path(__file__).parent
        self.loxs_script = self.script_dir / "loxs.py"
        
    def create_batch_files(self, url_file: str, batch_size: int = 50) -> list:
        """Split large URL file into manageable batches"""
        print(f"{Colors.CYAN}[BATCH]{Colors.RESET} Creating batches from {url_file}...")
        
        with open(url_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        
        if not urls:
            return []
            
        # Shuffle URLs for better distribution
        random.shuffle(urls)
        
        batch_files = []
        for i in range(0, len(urls), batch_size):
            batch = urls[i:i + batch_size]
            batch_file = f"{url_file}_batch_{i//batch_size + 1}.txt"
            
            with open(batch_file, 'w') as f:
                for url in batch:
                    f.write(f"{url}\n")
            
            batch_files.append(batch_file)
        
        print(f"{Colors.GREEN}[SUCCESS]{Colors.RESET} Created {len(batch_files)} batch files")
        return batch_files
    
    def run_loxs_scan(self, url_file: str, scan_type: str, output_suffix: str = ""):
        """Run a single LOXS scan with automated input"""
        scan_names = {'1': 'LFI', '2': 'OR', '3': 'SQLi', '4': 'XSS', '5': 'CRLF'}
        scan_name = scan_names.get(scan_type, f"Type-{scan_type}")
        
        print(f"{Colors.BOLD}[LOXS-{scan_name}]{Colors.RESET} Starting scan on {url_file}")
        
        try:
            # Create automated input sequence
            # Format: scan_type -> file_path -> thread_count -> save_results -> exit
            input_sequence = f"{scan_type}\n{url_file}\n\n5\ny\n7\n"
            
            # Run LOXS with timeout
            process = subprocess.Popen(
                [sys.executable, str(self.loxs_script)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=str(self.script_dir)
            )
            
            # Send input and wait for completion
            stdout, stderr = process.communicate(input=input_sequence, timeout=180)
            
            # Parse results
            vulnerabilities_found = 0
            if "vulnerable" in stdout.lower() or "found" in stdout.lower():
                # Try to extract vulnerability count
                lines = stdout.split('\n')
                for line in lines:
                    if "vulnerable" in line.lower() and any(char.isdigit() for char in line):
                        # Extract numbers from the line
                        numbers = [int(s) for s in line.split() if s.isdigit()]
                        if numbers:
                            vulnerabilities_found = max(numbers)
                            break
                
                if vulnerabilities_found == 0:
                    vulnerabilities_found = 1  # At least one found
            
            if vulnerabilities_found > 0:
                print(f"{Colors.RED}[VULN]{Colors.RESET} {scan_name}: {vulnerabilities_found} vulnerabilities found!")
            else:
                print(f"{Colors.GREEN}[CLEAN]{Colors.RESET} {scan_name}: No vulnerabilities detected")
                
            return vulnerabilities_found
            
        except subprocess.TimeoutExpired:
            print(f"{Colors.YELLOW}[TIMEOUT]{Colors.RESET} {scan_name} scan timed out")
            process.kill()
            return 0
        except Exception as e:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} {scan_name} scan failed: {str(e)[:100]}")
            return 0
    
    def run_batch_scanning(self, url_file: str, scan_types: list, batch_size: int = 50):
        """Run vulnerability scanning in batches"""
        print(f"{Colors.BOLD}{Colors.CYAN}[BATCH SCAN]{Colors.RESET} Processing {url_file}")
        
        # Create batches
        batch_files = self.create_batch_files(url_file, batch_size)
        
        if not batch_files:
            print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} No URLs to process")
            return
        
        total_vulns = {scan_type: 0 for scan_type in scan_types}
        
        # Process each batch
        for i, batch_file in enumerate(batch_files):
            print(f"\n{Colors.CYAN}[BATCH {i+1}/{len(batch_files)}]{Colors.RESET} Processing {batch_file}")
            
            for scan_type in scan_types:
                vulns = self.run_loxs_scan(batch_file, scan_type, f"_batch_{i+1}")
                total_vulns[scan_type] += vulns
                
                # Small delay between scans
                time.sleep(2)
            
            # Clean up batch file
            try:
                os.remove(batch_file)
            except:
                pass
        
        # Summary
        print(f"\n{Colors.BOLD}[SUMMARY]{Colors.RESET} Batch scanning completed:")
        scan_names = {'1': 'LFI', '2': 'OR', '3': 'SQLi', '4': 'XSS', '5': 'CRLF'}
        
        total_found = 0
        for scan_type, count in total_vulns.items():
            scan_name = scan_names.get(scan_type, scan_type)
            if count > 0:
                print(f"  {Colors.RED}🎯 {scan_name}: {count} vulnerabilities{Colors.RESET}")
                total_found += count
            else:
                print(f"  {Colors.GREEN}✅ {scan_name}: Clean{Colors.RESET}")
        
        print(f"\n{Colors.BOLD}Total Vulnerabilities Found: {Colors.RED if total_found > 0 else Colors.GREEN}{total_found}{Colors.RESET}")
    
    def run_gf_targeted_scan(self, gf_dir: str):
        """Run targeted scans based on GF pattern results"""
        gf_path = Path(gf_dir)
        if not gf_path.exists():
            print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} GF directory not found: {gf_dir}")
            return
        
        print(f"{Colors.CYAN}[GF SCAN]{Colors.RESET} Running targeted scans on GF patterns...")
        
        # Map GF patterns to LOXS scan types
        pattern_mapping = {
            'local-file-inclusion.txt': '1',      # LFI
            'open-redirect.txt': '2',             # OR  
            'sql-injection.txt': '3',             # SQLi
            'cross-site-scripting.txt': '4',      # XSS
        }
        
        for pattern_file, scan_type in pattern_mapping.items():
            file_path = gf_path / pattern_file
            if file_path.exists() and file_path.stat().st_size > 0:
                # Check file size and sample if needed
                line_count = int(subprocess.run(['wc', '-l', str(file_path)], 
                                              capture_output=True, text=True).stdout.split()[0])
                
                if line_count > 100:
                    # Sample the file
                    sampled_file = str(file_path) + "_sampled"
                    subprocess.run(['head', '-n', '100', str(file_path)], 
                                 stdout=open(sampled_file, 'w'))
                    self.run_loxs_scan(sampled_file, scan_type)
                    os.remove(sampled_file)
                else:
                    self.run_loxs_scan(str(file_path), scan_type)

def main():
    """Main function with CLI"""
    import argparse
    
    parser = argparse.ArgumentParser(description='LOXS Wrapper - Automated vulnerability scanning')
    parser.add_argument('-f', '--file', required=True, help='URL file to scan')
    parser.add_argument('-t', '--types', nargs='+', choices=['1', '2', '3', '4', '5'], 
                       default=['1', '2', '3', '4'], help='Scan types (1=LFI, 2=OR, 3=SQLi, 4=XSS, 5=CRLF)')
    parser.add_argument('-b', '--batch-size', type=int, default=50, help='Batch size (default: 50)')
    parser.add_argument('-g', '--gf-dir', help='GF patterns directory for targeted scanning')
    
    args = parser.parse_args()
    
    if not Path(args.file).exists():
        print(f"{Colors.RED}[ERROR]{Colors.RESET} URL file not found: {args.file}")
        return 1
    
    # Banner
    print(f"""
{Colors.CYAN}{Colors.BOLD}
╔════════════════════════════════════════════════════════╗
║                                                        ║
║            🎯 LOXS Smart Wrapper 🎯                    ║
║                                                        ║
║         Automated Vulnerability Scanning              ║
║                                                        ║
╚════════════════════════════════════════════════════════╝
{Colors.RESET}
    """)
    
    wrapper = LoxsWrapper()
    
    try:
        # Check if original loxs.py exists
        if not wrapper.loxs_script.exists():
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Original loxs.py not found!")
            return 1
        
        # Run batch scanning
        wrapper.run_batch_scanning(args.file, args.types, args.batch_size)
        
        # Run GF targeted scans if directory provided
        if args.gf_dir:
            wrapper.run_gf_targeted_scan(args.gf_dir)
        
        print(f"\n{Colors.GREEN}[COMPLETE]{Colors.RESET} LOXS wrapper finished!")
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[INTERRUPTED]{Colors.RESET} Scan stopped by user")
        return 1
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.RESET} Wrapper failed: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
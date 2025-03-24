#!/usr/bin/env python3

import subprocess
import re
import json
import argparse
import concurrent.futures
import ipaddress
import time
import os
from datetime import datetime


def run_nmap_scan(target, scan_type="default", output_dir="./nmap_results"):
    """
    Run Nmap scan with specified options
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', str(target))
    output_file = f"{output_dir}/{target_name}_{scan_type}_{timestamp}"
    
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    scan_commands = {
        "default": ["-sS", "-sV", "-O", "--osscan-guess", "-T4", "--script=default", "-p-"],
        "quick": ["-sS", "-sV", "-T4", "--top-ports", "1000"],
        "vuln": ["-sS", "-sV", "-T4", "--script=vuln", "-p-"],
        "stealth": ["-sS", "-T2", "--data-length", "15", "--max-retries", "1", "-p", "22,23,80,443,445,3389,8080,8443"],
        "udp": ["-sU", "-sV", "--top-ports", "100"]
    }
    
    if scan_type not in scan_commands:
        print(f"[!] Unkwown scan type: {scan_type}. Using default.")
        scan_type = "default"
    
    cmd = ["nmap", "-oA", output_file] + scan_commands[scan_type] + [str(target)]
    
    print(f"[+] Running {scan_type} scan on {target}")
    print(f"[+] Command: {' '.join(cmd)}")

    try:
        start_time = time.time()
        process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        elapsed = time.time() - start_time
        
        if process.returncode == 0:
            print(f"[+] Scan completed in {elapsed:.2f} seconds: {output_file}")
            return {
                "target": str(target),
                "scan_type": scan_type,
                "output_file": output_file,
                "success": True,
                "elapsed": elapsed,
                "stdout": process.stdout
            }
        else:
            print(f"[!] Scan failed for {target}: {process.stderr}")
            return {
                "target": str(target),
                "scan_type": scan_type,
                "success": False,
                "error": process.stderr
            }
            
    except Exception as e:
        print(f"[!] Error running scan on {target}: {str(e)}") 
        return {
            "target": target,
            "scan_type": scan_type,
            "success": False,
            "error": str(e)
        }
        
def parse_nmap_output(nmap_result):
    """
    Parse Nmap output to extract useful information
    """
    if not nmap_result["success"]:
        return nmap_result
    
    output = nmap_result["stdout"]
    
    # Extract open ports
    open_ports = []
    port_pattern = re.compile(r'(\d+)\/(\w+)\s+(\w+)\s+(\S+)(?:\s+(.+))?')
    for line in output.split("\n"):
        if "open" in line and not line.startswith("|"):
            match = port_pattern.search(line)
            if match:
                port, protocol, state, service, version = match.groups()
                open_ports.append({
                    "port": port,
                    "protocol": protocol,
                    "state": state,
                    "service": service,
                    "version": version if version else ""
                    })
                
    # Extract OS detection
    os_info = []
    os_block = False
    for line in output.split('\n'):
        if "OS detection performed" in line:
            os_block = True
            continue
        
        if os_block and "OS:" in line:
            os_name = line.split("OS:")[1].strip()
            os_info.append(os_name)
            
        if os_block and not line.strip():
            os_block = False
        
        nmap_result["parsed"] = {
            "open_ports": open_ports, 
            "os_info": os_info
        }
        
    return nmap_result

def scan_target_range(target_range, scan_types=["default"], max_workers=5, output_dir="./nmap_results"):
    """
    Scan a range of targets with multiple scan types
    """
    try:
        targets = list(ipaddress.IPv4Network(target_range))
    except ValueError:
        # If not a CIDR range, treat as single IP or hostname
        targets = [target_range]
        
    total_scans = len(targets) * len(scan_types)
    print(f"[+] Preparing to run {total_scans} scans against {len(targets)} targets")
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for target in targets:
            for scan_type in scan_types:
                futures.append(
                    executor.submit(run_nmap_scan, target, scan_type, output_dir)
                )
                
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            parsed_result = parse_nmap_output(result)
            results.append(parsed_result)
            
    return results


def generate_report(results, output_file="nmap_report.json"):
    """
    Generate a report from scan results
    """
    
    # Group results by target
    targets = {}
    for result in results:
        target = result["target"]
        if target not in targets:
            targets[target] = []
            
        targets[target].append(result)
        
    # Create report structure
    report = {
        "scan_summary": {
            "total_targets": len(targets),
            "total_scans": len(results),
            "timestamp": datetime.now().isoformat(),
            "successful_scans": len([r for r in results if r["success"]])
        },
        "targets": {}
    }
    
    # Process each target
    for target, target_results in targets.items():
        target_info = {
            "scans": {},
            "open_ports": [],
            "os_info": []
        }
        
    for result in target_results:
        scan_type = result["scan_type"]
        target_info["scans"][scan_type] = {
            "success": result["success"],
            "elapsed": result.get("elapsed", 0),
            "output_file": result.get("output_file", "")
        }
        
        if result["success"] and "parsed" in result:
            # Add open ports from this scan
            for port in result["parsed"]["open_ports"]:
                if port not in target_info["open_ports"]:
                    target_info["open_ports"].append(port)
                    
            # Add OS info from this scan
            for os in result["parsed"]["os_info"]:
                if os not in target_info["os_info"]:
                    target_info["os_info"].append(os)
                    
    report["targets"][target] = target_info
    
    # Write report to file
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=4)
        
    print(f"[+] Report saved to {output_file}")
    
    # Print summary
    print("\n=== Scan Summary ===")
    print(f"Total targets scanned: {report['scan_summary']['total_targets']}")
    print(f"Total scans run: {report['scan_summary']['total_scans']}")
    print(f"Successful scans: {report['scan_summary']['successful_scans']}")
    
    # Print interesting findings
    print("\n=== Interesting Findings ===")
    for target, info in report["targets"].items():
        if info["open_ports"]:
            print(f"\nTarget: {target}")
            print("  Open ports:")
            for port in info["open_ports"]:
                print(f"    {port['port']}/{port['protocol']} - {port['service']} {port['version']}")
            
            if info["os_info"]:
                print("  OS detection:")
                for os in info["os_info"]:
                    print(f"    {os}")
    
    return report


def main():
    parser = argparse.ArgumentParser(description="Service Enum Script")
    parser.add_argument('-t', '--target', required=True, help='Target IP, hostname, or CIDR range')
    parser.add_argument('-s', '--scan-types', default='default', help='Scan types to run (comma-separated): default,quick,vuln,stealth,udp')
    parser.add_argument('-w', '--workers', default=5, help='Maximum parallel scans')
    parser.add_argument('-o', '--output-dir', default='./nmap_results', help='Output directory for scan results')
    parser.add_argument('-r', '--report', default='nmap_report.json', help='Output file for JSON report')
    args = parser.parse_args()
    
    scan_types = args.scan_types.split(',')
    print(f"[+] Starting Nmap scanning against {args.target}")
    results = scan_target_range(args.target, scan_types, args.workers, args.output_dir)
    generate_report(results, args.report)


if __name__ == "__main__":
    main()
    
    

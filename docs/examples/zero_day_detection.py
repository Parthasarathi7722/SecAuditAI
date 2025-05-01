#!/usr/bin/env python3
"""
Zero-Day Detection Example
-------------------------
This example demonstrates how to use SecAuditAI's experimental zero-day
vulnerability detection feature. Note: This is an experimental feature
and should be used with caution.
"""

from secauditai import ZeroDayScanner
from secauditai.reports import generate_zero_day_report

def main():
    # Initialize zero-day scanner
    scanner = ZeroDayScanner()
    
    # Enable experimental features
    scanner.enable_experimental()
    
    # Scan code repository
    print("Scanning code repository for zero-day vulnerabilities...")
    code_results = scanner.scan_code(
        path="/path/to/code",
        languages=["python", "javascript", "java"],
        check_patterns=True,
        check_behavior=True,
        check_dependencies=True
    )
    
    # Analyze network traffic
    print("\nAnalyzing network traffic patterns...")
    network_results = scanner.analyze_network(
        pcap_file="network_traffic.pcap",
        duration=600,  # 10 minutes
        check_protocols=True,
        check_payloads=True
    )
    
    # Generate comprehensive report
    report = generate_zero_day_report(
        code_results=code_results,
        network_results=network_results,
        format="html",
        include_experimental=True
    )
    
    # Save report
    with open("zero_day_report.html", "w") as f:
        f.write(report)
    
    print("\nZero-day detection report generated: zero_day_report.html")
    print("Note: This is an experimental feature. Results should be verified manually.")

if __name__ == "__main__":
    main() 
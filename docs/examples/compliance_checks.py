#!/usr/bin/env python3
"""
Compliance Checks Example
------------------------
This example demonstrates how to use SecAuditAI for performing compliance
checks against various security frameworks and standards.
"""

from secauditai import ComplianceChecker
from secauditai.reports import generate_compliance_report

def main():
    # Initialize compliance checker
    checker = ComplianceChecker()
    
    # Run CIS Benchmark checks
    print("Running CIS Benchmark checks...")
    cis_results = checker.check_cis(
        framework="cis-1.5",  # Options: cis-1.5, cis-2.0
        level=2,  # Options: 1, 2
        sections=["1", "2", "3"]  # Specific sections to check
    )
    
    # Run PCI DSS compliance check
    print("\nRunning PCI DSS compliance check...")
    pci_results = checker.check_pci(
        version="4.0",
        requirements=["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12"]
    )
    
    # Run HIPAA compliance check
    print("\nRunning HIPAA compliance check...")
    hipaa_results = checker.check_hipaa(
        rules=["Security", "Privacy", "Breach Notification"]
    )
    
    # Run NIST compliance check
    print("\nRunning NIST compliance check...")
    nist_results = checker.check_nist(
        framework="800-53",
        controls=["AC", "AT", "AU", "CA", "CM", "CP", "IA", "MA", "MP", "PE", "PL", "PS", "RA", "SA", "SC", "SI", "SR"]
    )
    
    # Generate comprehensive report
    report = generate_compliance_report(
        cis_results=cis_results,
        pci_results=pci_results,
        hipaa_results=hipaa_results,
        nist_results=nist_results,
        format="html"
    )
    
    # Save report
    with open("compliance_report.html", "w") as f:
        f.write(report)
    
    print("\nCompliance report generated: compliance_report.html")

if __name__ == "__main__":
    main() 